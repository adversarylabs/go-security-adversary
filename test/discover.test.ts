import assert from "node:assert/strict";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import test from "node:test";
import { discoverSources } from "../src/discover.js";

const execute = promisify(execFile);

async function git(repo: string, ...args: string[]): Promise<void> {
  await execute("git", ["-C", repo, ...args]);
}

async function initRepo(): Promise<string> {
  const repo = await mkdtemp(join(tmpdir(), "go-security-discover-"));
  await git(repo, "init");
  await git(repo, "config", "user.email", "t@example.com");
  await git(repo, "config", "user.name", "t");
  await writeFile(join(repo, "main.go"), "package main\n\nfunc main() {}\n");
  await git(repo, "add", ".");
  await git(repo, "commit", "-m", "init");
  return repo;
}

test("discoverSources reads untracked paths from change.changedFiles", async () => {
  const repo = await initRepo();
  await mkdir(join(repo, "pkg", "weak"), { recursive: true });
  await writeFile(
    join(repo, "pkg", "weak", "tls.go"),
    `package weak

import "crypto/tls"

func C() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }
`,
  );

  const discovery = await discoverSources(repo, {
    type: "diff",
    baseRef: "HEAD",
    headRef: "WORKTREE",
    scanMode: "changed",
    changedFiles: ["pkg/weak/tls.go"],
    worktree: true,
  });

  assert.equal(discovery.mode, "diff");
  assert.equal(discovery.files.length, 1);
  assert.equal(discovery.files[0]?.path, "pkg/weak/tls.go");
  assert.equal(discovery.files[0]?.status, "added");
  assert.match(discovery.files[0]?.current ?? "", /InsecureSkipVerify/);
});

test("discoverSources --all includes untracked Go files", async () => {
  const repo = await initRepo();
  await mkdir(join(repo, "pkg", "weak"), { recursive: true });
  await writeFile(
    join(repo, "pkg", "weak", "tls.go"),
    "package weak\n\nfunc W() {}\n",
  );

  const discovery = await discoverSources(repo, {
    type: "diff",
    baseRef: "HEAD",
    headRef: "HEAD",
    scanMode: "all",
    changedFiles: [],
    worktree: false,
  });

  assert.ok(
    discovery.files.some((file) => file.path === "pkg/weak/tls.go"),
    `expected untracked plant in all-files discovery, got ${discovery.files.map((f) => f.path).join(",")}`,
  );
});
