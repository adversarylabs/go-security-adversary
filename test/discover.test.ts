import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import test from "node:test";
import type { RuleContext } from "@adversarylabs/sdk";
import { loadInScopeSources } from "@adversarylabs/sdk";
import { discoverSources } from "../src/discover.js";
import { createApp } from "../src/index.js";

const execute = promisify(execFile);

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

test("diff discovery hydrates only unchanged direct sibling packages in the changed service family", async () => {
  const repo = await mkdtemp(join(tmpdir(), "go-sec-discover-family-"));
  const workloadPath = "pkg/agent/endpoints/workload/handler.go";
  const sdsPath = "pkg/agent/endpoints/sdsv3/handler.go";
  const legacyPath = "pkg/agent/endpoints/legacy/cookie.go";
  const malformedContextPath = "pkg/agent/endpoints/legacy/broken.go";
  const unrelatedPath = "pkg/server/admin/handler.go";
  for (const path of [workloadPath, sdsPath, legacyPath, malformedContextPath, unrelatedPath]) {
    await mkdir(join(repo, ...path.split("/").slice(0, -1)), { recursive: true });
  }
  await execute("git", ["init", "--quiet"], { cwd: repo });
  await execute("git", ["config", "user.email", "tests@example.com"], { cwd: repo });
  await execute("git", ["config", "user.name", "Tests"], { cwd: repo });
  await writeFile(join(repo, workloadPath), establishedWorkloadExemption);
  await writeFile(join(repo, sdsPath), sdsBeforeRateLimit);
  await writeFile(join(repo, legacyPath), legacyAuthenticationCookie);
  await writeFile(join(repo, malformedContextPath), "package legacy\nfunc broken(\n");
  await writeFile(join(repo, unrelatedPath), establishedWorkloadExemption.replace("package workload", "package admin"));
  await execute("git", ["add", "."], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "fixture"], { cwd: repo });
  await writeFile(join(repo, sdsPath), vulnerableSDS);

  const change: RuleContext["change"] = {
    type: "diff",
    baseRef: "HEAD",
    headRef: "WORKTREE",
    scanMode: "changed",
    changedFiles: [sdsPath],
    worktree: true,
  };
  const discovery = await discoverSources(fakeCtx(repo, change));

  assert.deepEqual(
    discovery.files.map((file) => file.path),
    [malformedContextPath, legacyPath, sdsPath, workloadPath],
  );
  assert.equal(discovery.files.find((file) => file.path === workloadPath)?.status, "context");
  assert.equal(discovery.files.find((file) => file.path === legacyPath)?.status, "context");
  assert.equal(discovery.files.find((file) => file.path === sdsPath)?.status, "modified");
  assert.equal(discovery.files.some((file) => file.path === unrelatedPath), false);

  const output = await createApp().run({
    input: {
      source: { path: repo },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: [sdsPath],
      },
    },
  });
  assert.equal(output.findings.some((item) => item.ruleId === "go-security.rate-limit.self-denial"), true);
  assert.equal(output.findings.some((item) => item.ruleId === "go-security.cookie.auth-httponly"), false);
  assert.equal(output.observations.some((item) => /parse error/i.test(item.summary)), false);
});

test("an unrelated edit does not surface a legacy authentication cookie finding", async () => {
  const repo = await repositoryWithLegacyCookie();
  const path = "handler.go";
  await writeFile(join(repo, path), cookieSource("new diagnostic"));
  const change: RuleContext["change"] = {
    type: "diff",
    baseRef: "HEAD",
    headRef: "WORKTREE",
    scanMode: "changed",
    changedFiles: [path],
    worktree: true,
  };

  const discovery = await discoverSources(fakeCtx(repo, change));
  assert.equal(discovery.files[0]?.status, "modified");
  assert.deepEqual([...discovery.files[0]!.changedLines], [9]);

  const output = await createApp().run({
    input: {
      source: { path: repo },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: [path],
      },
    },
  });
  assert.equal(output.findings.some((item) => item.ruleId === "go-security.cookie.auth-httponly"), false);
});

test("a newly added file remains eligible in full", async () => {
  const repo = await repositoryWithLegacyCookie();
  const path = "added.go";
  await writeFile(join(repo, path), cookieSource("added"));
  const change: RuleContext["change"] = {
    type: "diff",
    baseRef: "HEAD",
    headRef: "WORKTREE",
    scanMode: "changed",
    changedFiles: [path],
    worktree: true,
  };

  const discovery = await discoverSources(fakeCtx(repo, change));
  assert.equal(discovery.files[0]?.status, "added");

  const output = await createApp().run({
    input: {
      source: { path: repo },
      change: {
        type: "diff",
        base_ref: "HEAD",
        head_ref: "WORKTREE",
        scan_mode: "changed",
        changed_files: [path],
      },
    },
  });
  assert.equal(output.findings.some((item) => item.ruleId === "go-security.cookie.auth-httponly"), true);
});

async function repositoryWithLegacyCookie(): Promise<string> {
  const repo = await mkdtemp(join(tmpdir(), "go-sec-discover-git-"));
  await execute("git", ["init", "--quiet"], { cwd: repo });
  await execute("git", ["config", "user.email", "tests@example.com"], { cwd: repo });
  await execute("git", ["config", "user.name", "Tests"], { cwd: repo });
  await writeFile(join(repo, "handler.go"), cookieSource("old diagnostic"));
  await execute("git", ["add", "handler.go"], { cwd: repo });
  await execute("git", ["commit", "--quiet", "-m", "fixture"], { cwd: repo });
  return repo;
}

function cookieSource(diagnostic: string): string {
  return `package fixture
import "net/http"
func login(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{Name: "session", Value: token})
}
func diagnostic() {
	println(
		"security",
		${JSON.stringify(diagnostic)},
	)
}
`;
}

const establishedWorkloadExemption = `package workload
import (
  "context"
  "os"
  "example.test/spire/pkg/agent/api/rpccontext"
)
type Limiter interface { RateLimit(string, []string) error }
type Config struct { RateLimiter Limiter }
type Handler struct { c Config }
func isAgent(ctx context.Context) bool {
  return rpccontext.CallerPID(ctx) == os.Getpid()
}
func (h *Handler) rateLimit(method string, selectors []string) error {
  return h.c.RateLimiter.RateLimit(method, selectors)
}
func (h *Handler) FetchX509SVID(ctx context.Context, selectors []string) error {
  if !isAgent(ctx) {
    if err := h.rateLimit("FetchX509SVID", selectors); err != nil { return err }
  }
  return nil
}
// The agent health check exercises this API, so agent-self calls are exempt.
`;

const vulnerableSDS = `package sdsv3
import "context"
type Limiter interface { RateLimit(string, []string) error }
type Config struct { RateLimiter Limiter }
type Handler struct { c Config }
func (h *Handler) rateLimit(method string, selectors []string) error {
  if h.c.RateLimiter == nil { return nil }
  return h.c.RateLimiter.RateLimit(method, selectors)
}
func (h *Handler) StreamSecrets(ctx context.Context, selectors []string) error {
  if err := h.rateLimit("StreamSecrets", selectors); err != nil { return err }
  return nil
}
`;

const sdsBeforeRateLimit = vulnerableSDS.replace(
  '  if err := h.rateLimit("StreamSecrets", selectors); err != nil { return err }\n',
  "",
);

const legacyAuthenticationCookie = `package legacy
import "net/http"
func login(w http.ResponseWriter, token string) {
  http.SetCookie(w, &http.Cookie{Name: "session", Value: token})
}
`;
