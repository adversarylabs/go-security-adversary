import { execFile } from "node:child_process";
import type { Dirent } from "node:fs";
import { readdir, readFile, realpath, stat } from "node:fs/promises";
import { join, posix, relative, sep } from "node:path";
import { promisify } from "node:util";
import type { RuleContext } from "@adversarylabs/sdk";
import { domain } from "./domain.js";
import { type Discovery, type SourceRevision } from "./types.js";

const MAX_FILE_BYTES = 750_000;
const MAX_FILES = 750;
const MAX_CONTEXT_FILES = 250;
const SIBLING_CONTEXT_TRIGGER = /(?:rate.?limit|limiter|quota)/i;
const CONTEXT_EXCLUDED_PATH = /(?:^|\/)(?:vendor|testdata|generated|mocks?|fakes?)(?:\/|$)/i;
const execute = promisify(execFile);

/**
 * Load Go sources for the runner's review scope.
 *
 * Scope ownership lives in the CLI/SDK (`change.changedFiles` includes untracked
 * worktree paths; `--all-files` walks the target). Git is used only to classify
 * those already-scoped paths and recover their changed line ranges.
 */
export async function discoverSources(ctx: RuleContext): Promise<Discovery> {
  const sources = await ctx.loadInScopeSources({
    include: domain.includePath,
    limit: MAX_FILES,
    maxBytes: MAX_FILE_BYTES,
  });

  const wholeTarget = ctx.change === null || ctx.change.scanMode === "all";
  const files: SourceRevision[] = [];
  for (const source of sources) {
    if (source.status === "repository") {
      files.push({
        path: source.path,
        current: source.content,
        changedLines: new Set<number>(),
        status: "repository",
      });
      continue;
    }

    const change = await changedSource(ctx, source.path);
    files.push({
      path: source.path,
      current: source.content,
      ...(change.previous === undefined ? {} : { previous: change.previous }),
      changedLines: change.changedLines,
      status: change.status,
    });
  }

  if (!wholeTarget && files.length < MAX_FILES) {
    files.push(...await siblingFamilySources(ctx, files, MAX_FILES - files.length));
  }
  files.sort((left, right) => left.path.localeCompare(right.path));

  return {
    mode: wholeTarget ? "repository" : "diff",
    ...(ctx.change?.baseRef === undefined ? {} : { base: ctx.change.baseRef }),
    files,
  };
}

/**
 * Load only the unchanged package siblings needed to compare a changed service
 * endpoint with an established peer contract. For a changed path such as
 * pkg/agent/endpoints/sdsv3/handler.go, the family is pkg/agent/endpoints and
 * only direct Go files in its child packages are eligible. This is deliberately
 * narrower than a repository-wide Go scan.
 */
async function siblingFamilySources(
  ctx: RuleContext,
  files: SourceRevision[],
  remainingFileBudget: number,
): Promise<SourceRevision[]> {
  const limit = Math.min(MAX_CONTEXT_FILES, remainingFileBudget);
  if (limit <= 0) return [];

  const knownPaths = new Set(files.map((file) => normalizeRepoPath(file.path)));
  const families = new Set<string>();
  for (const file of files) {
    if (file.status === "repository") continue;
    if (!SIBLING_CONTEXT_TRIGGER.test(file.current)) continue;
    const family = serviceFamily(file.path);
    if (family !== undefined) families.add(family);
  }

  const repoRoot = await realpath(ctx.repoPath);
  const contextual: SourceRevision[] = [];
  for (const family of [...families].sort()) {
    if (contextual.length >= limit) break;
    const familyPath = await safeFamilyPath(repoRoot, family);
    if (familyPath === undefined) continue;

    let packageEntries: Dirent[];
    try {
      packageEntries = await readdir(familyPath, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const packageEntry of packageEntries.sort((left, right) => left.name.localeCompare(right.name))) {
      if (contextual.length >= limit || !packageEntry.isDirectory()) continue;
      const packagePath = join(familyPath, packageEntry.name);
      let sourceEntries: Dirent[];
      try {
        sourceEntries = await readdir(packagePath, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const sourceEntry of sourceEntries.sort((left, right) => left.name.localeCompare(right.name))) {
        if (contextual.length >= limit || !sourceEntry.isFile()) continue;
        const path = posix.join(family, packageEntry.name, sourceEntry.name);
        if (knownPaths.has(path) || !domain.includePath(path) || CONTEXT_EXCLUDED_PATH.test(path)) continue;
        try {
          const absolutePath = await safeExistingPath(repoRoot, join(packagePath, sourceEntry.name));
          if (absolutePath === undefined) continue;
          const metadata = await stat(absolutePath);
          if (!metadata.isFile() || metadata.size > MAX_FILE_BYTES) continue;
          const current = await readFile(absolutePath, "utf8");
          if (Buffer.byteLength(current, "utf8") > MAX_FILE_BYTES) continue;
          contextual.push({
            path,
            current,
            changedLines: new Set<number>(),
            status: "context",
          });
          knownPaths.add(path);
        } catch {
          // A disappearing or unreadable sibling is not reliable evidence.
        }
      }
    }
  }
  return contextual;
}

function serviceFamily(path: string): string | undefined {
  const normalized = normalizeRepoPath(path);
  if (!domain.includePath(normalized)) return undefined;
  const family = posix.dirname(posix.dirname(normalized));
  const parts = family.split("/");
  if (family === "." || parts.length < 2 || parts.some((part) => part === "" || part === "." || part === "..")) {
    return undefined;
  }
  return family;
}

function normalizeRepoPath(path: string): string {
  return path.replaceAll("\\", "/").replace(/^\.\//, "");
}

async function safeFamilyPath(repoRoot: string, family: string): Promise<string | undefined> {
  return safeExistingPath(repoRoot, join(repoRoot, ...family.split("/")));
}

async function safeExistingPath(repoRoot: string, path: string): Promise<string | undefined> {
  try {
    const candidate = await realpath(path);
    const fromRoot = relative(repoRoot, candidate);
    if (fromRoot === ".." || fromRoot.startsWith(`..${sep}`)) return undefined;
    return candidate;
  } catch {
    return undefined;
  }
}

async function changedSource(
  ctx: RuleContext,
  path: string,
): Promise<Pick<SourceRevision, "changedLines" | "status" | "previous">> {
  const base = ctx.change?.baseRef;
  if (base === undefined || !(await existsAtRevision(ctx.repoPath, base, path))) {
    return { changedLines: new Set<number>(), status: "added" };
  }

  const args = ["diff", "--unified=0", base];
  const head = ctx.change?.headRef;
  if (head !== undefined && !ctx.change?.worktree) args.push(head);
  args.push("--", path);
  const patch = await gitOutput(ctx.repoPath, args);
  let previous: string | undefined;
  try {
    previous = await gitOutput(ctx.repoPath, ["show", `${base}:${path}`]);
  } catch {
    previous = undefined;
  }
  return {
    changedLines: changedLineNumbers(patch),
    status: "modified",
    ...(previous === undefined ? {} : { previous }),
  };
}

async function existsAtRevision(repoPath: string, revision: string, path: string): Promise<boolean> {
  try {
    await execute("git", ["-C", repoPath, "cat-file", "-e", `${revision}:${path}`], {
      maxBuffer: 1024 * 1024,
    });
    return true;
  } catch {
    return false;
  }
}

async function gitOutput(repoPath: string, args: string[]): Promise<string> {
  const result = await execute("git", ["-C", repoPath, ...args], {
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  return result.stdout;
}

function changedLineNumbers(patch: string): Set<number> {
  const lines = new Set<number>();
  for (const match of patch.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) {
    const start = Number(match[1]);
    const count = match[2] === undefined ? 1 : Number(match[2]);
    for (let line = start; line < start + count; line += 1) lines.add(line);
  }
  return lines;
}
