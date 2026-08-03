import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import type { RuleContext } from "@adversarylabs/sdk";
import { loadInScopeSources } from "@adversarylabs/sdk";
import { discoverSources } from "../src/discover.js";

function fakeCtx(
  repoPath: string,
  change: RuleContext["change"],
): RuleContext {
  return {
    repoPath,
    change,
    repoIndex: null,
    summary: {},
    cache: new Map(),
    relpath: (path) => path,
    glob: async () => [],
    rglob: async () => [],
    listInScopePaths: async (options) => {
      const { listInScopePaths } = await import("@adversarylabs/sdk");
      return listInScopePaths(repoPath, change, options);
    },
    loadInScopeSources: async (options) => loadInScopeSources(repoPath, change, options),
    model: {
      review: async () => {
        throw new Error("unused");
      },
      concern: async () => {
        throw new Error("unused");
      },
    } as unknown as RuleContext["model"],
    observe: () => {},
    finding: () => {},
    review: {
      assessment: () => {},
      positive: () => {},
      observe: () => {},
      score: () => {},
      opinion: () => {},
    },
  };
}

test("discoverSources uses CLI changedFiles (untracked) without git", async () => {
  const repo = await mkdtemp(join(tmpdir(), "go-sec-discover-"));
  await mkdir(join(repo, "pkg", "weak"), { recursive: true });
  await writeFile(
    join(repo, "pkg", "weak", "tls.go"),
    `package weak

import "crypto/tls"

func C() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }
`,
  );

  const discovery = await discoverSources(
    fakeCtx(repo, {
      type: "diff",
      baseRef: "HEAD",
      headRef: "WORKTREE",
      scanMode: "changed",
      changedFiles: ["pkg/weak/tls.go"],
      worktree: true,
    }),
  );

  assert.equal(discovery.mode, "diff");
  assert.equal(discovery.files.length, 1);
  assert.equal(discovery.files[0]?.path, "pkg/weak/tls.go");
  assert.equal(discovery.files[0]?.status, "added");
  assert.match(discovery.files[0]?.current ?? "", /InsecureSkipVerify/);
});

test("discoverSources all-files walks target via SDK", async () => {
  const repo = await mkdtemp(join(tmpdir(), "go-sec-discover-all-"));
  await mkdir(join(repo, "pkg", "weak"), { recursive: true });
  await writeFile(join(repo, "main.go"), "package main\n");
  await writeFile(join(repo, "pkg", "weak", "tls.go"), "package weak\n");
  await writeFile(join(repo, "skip.txt"), "nope\n");

  const discovery = await discoverSources(
    fakeCtx(repo, {
      type: "diff",
      baseRef: "HEAD",
      headRef: "HEAD",
      scanMode: "all",
      changedFiles: [],
      worktree: false,
    }),
  );

  assert.equal(discovery.mode, "repository");
  const paths = discovery.files.map((f) => f.path).sort();
  assert.deepEqual(paths, ["main.go", "pkg/weak/tls.go"]);
});
