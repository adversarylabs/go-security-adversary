import { execFile } from "node:child_process";
import { readFile, readdir } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { promisify } from "node:util";
import { type ChangeContext } from "@adversarylabs/sdk";
import { domain } from "./domain.js";
import { type Discovery, type SourceRevision } from "./types.js";

const execute = promisify(execFile);
const IGNORED_DIRECTORIES = new Set([
  ".git", "build", "dist", "generated", "node_modules", "third_party", "vendor",
]);
const MAX_FILE_BYTES = 750_000;
const MAX_FILES = 750;

export async function discoverSources(
  repoPath: string,
  change: ChangeContext | null,
): Promise<Discovery> {
  if (!(await isGitRepository(repoPath)) || !(await revisionExists(repoPath, "HEAD"))) {
    return { mode: "repository", files: await readSources(repoPath, await repositoryFiles(repoPath)) };
  }

  // Explicit whole-target reviews must not collapse to a tiny incidental diff.
  if (change !== null && change.scanMode === "all") {
    return trackedRepository(repoPath);
  }

  // Prefer the CLI's authoritative change list (includes untracked). Re-running
  // `git diff` alone misses untracked files that ResolveRunScope already listed.
  if (
    change !== null &&
    change.scanMode === "changed" &&
    change.changedFiles.length > 0
  ) {
    return listedChangeDiscovery(
      repoPath,
      change.changedFiles,
      change.baseRef ?? "HEAD",
    );
  }

  if (change !== null && change.scanMode === "changed" &&
    change.baseRef !== undefined && (await revisionExists(repoPath, change.baseRef))) {
    const head = change.worktree ? [] : ["HEAD"];
    const names = await gitOutput(
      repoPath,
      ["diff", "--name-status", "--find-renames", change.baseRef, ...head, "--"],
    );
    return diffDiscovery(repoPath, change.baseRef, names);
  }

  // Auto: dirty worktree vs HEAD, then branch base vs HEAD, else whole repository.
  const worktree = await gitOutput(repoPath, ["diff", "--name-status", "--find-renames", "HEAD", "--"]);
  if (worktree.trim() !== "") return diffDiscovery(repoPath, "HEAD", worktree);

  const base = await chooseBase(repoPath);
  if (base !== undefined) {
    const names = await gitOutput(repoPath, ["diff", "--name-status", "--find-renames", base, "HEAD", "--"]);
    if (names.trim() !== "") return diffDiscovery(repoPath, base, names);
  }

  return trackedRepository(repoPath);
}

async function trackedRepository(repoPath: string): Promise<Discovery> {
  // Tracked + untracked (respecting .gitignore) so local plants are visible under --all-files.
  const tracked = (await gitOutput(repoPath, ["ls-files", "-z"])).split("\0");
  let untracked: string[] = [];
  try {
    untracked = (await gitOutput(repoPath, ["ls-files", "-z", "-o", "--exclude-standard"])).split("\0");
  } catch {
    untracked = [];
  }
  const seen = new Set<string>();
  const paths: string[] = [];
  for (const path of [...tracked, ...untracked]) {
    if (!path || seen.has(path) || !domain.includePath(path)) continue;
    seen.add(path);
    paths.push(path);
    if (paths.length >= MAX_FILES) break;
  }
  return { mode: "repository", files: await readSources(repoPath, paths) };
}

/** Load paths from the CLI change list (worktree-aware; untracked → added). */
async function listedChangeDiscovery(
  repoPath: string,
  changedFiles: readonly string[],
  base: string,
): Promise<Discovery> {
  const files: SourceRevision[] = [];
  for (const raw of changedFiles) {
    if (files.length >= MAX_FILES) break;
    const path = raw.replaceAll("\\", "/");
    if (!domain.includePath(path)) continue;
    const current = await safeRead(join(repoPath, path));
    if (current === undefined) continue;
    const tracked = await isTracked(repoPath, path);
    if (!tracked) {
      files.push({ path, current, changedLines: new Set(), status: "added" });
      continue;
    }
    const changedLines = await changedLineNumbers(repoPath, base, path);
    files.push({
      path,
      current,
      changedLines,
      status: changedLines.size === 0 ? "added" : "modified",
    });
  }
  return { mode: "diff", base, files };
}

async function isTracked(repoPath: string, path: string): Promise<boolean> {
  try {
    const out = await gitOutput(repoPath, ["ls-files", "--", path]);
    return out.trim().length > 0;
  } catch {
    return false;
  }
}

async function diffDiscovery(repoPath: string, base: string, names: string): Promise<Discovery> {
  const records = parseNameStatus(names)
    .filter((record) => record.status !== "D" && domain.includePath(record.path))
    .slice(0, MAX_FILES);
  const files: SourceRevision[] = [];
  for (const record of records) {
    const current = await safeRead(join(repoPath, record.path));
    if (current === undefined) continue;
    files.push({
      path: record.path,
      current,
      changedLines: await changedLineNumbers(repoPath, base, record.path),
      status: record.status === "A" ? "added" : "modified",
    });
  }
  return { mode: "diff", base, files };
}

async function readSources(repoPath: string, paths: string[]): Promise<SourceRevision[]> {
  const files: SourceRevision[] = [];
  for (const path of paths) {
    const current = await safeRead(join(repoPath, path));
    if (current === undefined) continue;
    files.push({ path, current, changedLines: new Set(), status: "repository" });
  }
  return files;
}

async function repositoryFiles(repoPath: string): Promise<string[]> {
  const files: string[] = [];
  async function visit(directory: string): Promise<void> {
    if (files.length >= MAX_FILES) return;
    let entries;
    try {
      entries = await readdir(join(repoPath, directory), { withFileTypes: true });
    } catch {
      return;
    }
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      if (files.length >= MAX_FILES) return;
      const relativePath = directory === "" ? entry.name : join(directory, entry.name);
      const posix = relativePath.split(sep).join("/");
      if (entry.isDirectory()) {
        if (!IGNORED_DIRECTORIES.has(entry.name)) await visit(posix);
        continue;
      }
      if (domain.includePath(posix)) files.push(posix);
    }
  }
  await visit("");
  return files;
}

async function changedLineNumbers(repoPath: string, base: string, path: string): Promise<Set<number>> {
  const lines = new Set<number>();
  try {
    const patch = await gitOutput(repoPath, ["diff", "--unified=0", base, "--", path]);
    let newLine = 0;
    for (const line of patch.split("\n")) {
      const header = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(line);
      if (header) {
        newLine = Number(header[1]);
        continue;
      }
      if (line.startsWith("+") && !line.startsWith("+++")) {
        lines.add(newLine);
        newLine += 1;
      } else if (line.startsWith("-") && !line.startsWith("---")) {
        // removed lines do not advance newLine
      } else if (!line.startsWith("\\")) {
        newLine += 1;
      }
    }
  } catch {
    // treat as fully changed
  }
  return lines;
}

function parseNameStatus(names: string): Array<{ status: string; path: string }> {
  return names
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const parts = line.split("\t");
      const status = (parts[0] ?? "M")[0] ?? "M";
      const path = parts.length > 2 ? parts[2]! : parts[1] ?? "";
      return { status, path };
    })
    .filter((record) => record.path.length > 0);
}

async function chooseBase(repoPath: string): Promise<string | undefined> {
  for (const candidate of ["main", "master", "trunk", "origin/main", "origin/master"]) {
    if (await revisionExists(repoPath, candidate)) {
      const head = await gitOutput(repoPath, ["rev-parse", "HEAD"]);
      const base = await gitOutput(repoPath, ["rev-parse", candidate]);
      if (head.trim() !== base.trim()) return candidate;
    }
  }
  return undefined;
}

async function isGitRepository(repoPath: string): Promise<boolean> {
  try {
    await gitOutput(repoPath, ["rev-parse", "--is-inside-work-tree"]);
    return true;
  } catch {
    return false;
  }
}

async function revisionExists(repoPath: string, rev: string): Promise<boolean> {
  try {
    await gitOutput(repoPath, ["rev-parse", "--verify", rev]);
    return true;
  } catch {
    return false;
  }
}

async function gitOutput(repoPath: string, args: string[]): Promise<string> {
  const { stdout } = await execute("git", ["-C", repoPath, ...args], {
    maxBuffer: 20 * 1024 * 1024,
    encoding: "utf8",
  });
  return stdout;
}

async function safeRead(path: string): Promise<string | undefined> {
  try {
    const buffer = await readFile(path);
    if (buffer.byteLength > MAX_FILE_BYTES) return undefined;
    if (buffer.includes(0)) return undefined;
    return buffer.toString("utf8");
  } catch {
    return undefined;
  }
}
