import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { copyFile, mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

const execute = promisify(execFile);
const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));

test("the published runtime executes without node_modules", async () => {
  const artifact = await mkdtemp(join(tmpdir(), "go-security-artifact-"));
  const repository = await mkdtemp(join(tmpdir(), "go-security-target-"));
  const entrypoint = join(artifact, "dist", "index.js");
  const noticesPath = join(artifact, "THIRD_PARTY_NOTICES.md");
  const input = join(artifact, "input.json");
  const output = join(artifact, "output.json");

  await mkdir(dirname(entrypoint), { recursive: true });
  await mkdir(join(artifact, "schemas"), { recursive: true });
  await copyFile(join(projectRoot, "dist", "index.js"), entrypoint);
  await copyFile(join(projectRoot, "THIRD_PARTY_NOTICES.md"), noticesPath);
  await copyFile(join(projectRoot, "dist", "web-tree-sitter.wasm"), join(artifact, "dist", "web-tree-sitter.wasm"));
  await copyFile(join(projectRoot, "dist", "tree-sitter-go.wasm"), join(artifact, "dist", "tree-sitter-go.wasm"));
  await copyFile(
    join(projectRoot, "schemas", "adversary.review.v1.schema.json"),
    join(artifact, "schemas", "adversary.review.v1.schema.json"),
  );
  await writeFile(join(artifact, "package.json"), '{"type":"module"}\n');
  await writeFile(join(repository, "main.go"), "package sample\n\nfunc ready() bool { return true }\n");
  await writeFile(input, `${JSON.stringify({ source: { path: repository } })}\n`);

  const bundle = await readFile(entrypoint, "utf8");
  assert.doesNotMatch(bundle, /from\s+["'](?:@adversarylabs\/sdk|web-tree-sitter)["']/);
  assert.doesNotMatch(bundle, /\/Users\/|\/private\/tmp\/|[A-Za-z]:\\\\Users\\\\/);
  const notices = await readFile(noticesPath, "utf8");
  assert.deepEqual([...notices.matchAll(/^## (.+?) \(/gm)].map((match) => match[1]), [
    "@adversarylabs/sdk",
    "ajv",
    "fast-deep-equal",
    "fast-uri",
    "json-schema-traverse",
    "tree-sitter-go",
    "web-tree-sitter",
    "yaml",
  ]);
  for (const section of notices.split(/^## /m).slice(1)) {
    assert.ok(section.length > 300, `expected a full license text, got ${section.length} bytes`);
    assert.match(section, /copyright|permission|redistribution|license/i);
  }

  await execute(process.execPath, [entrypoint], {
    cwd: artifact,
    env: {
      ...process.env,
      ADVERSARY_INPUT: input,
      ADVERSARY_OUTPUT: output,
      ADVERSARY_REPO: repository,
    },
  });

  const envelope = JSON.parse(await readFile(output, "utf8"));
  assert.equal(envelope.protocolVersion, 1);
  assert.equal(envelope.result.adversary.name, "go/security");
  assert.equal(envelope.result.adversary.version, "0.0.26");
  assert.deepEqual(envelope.result.findings, []);

  const workloadPath = "pkg/agent/endpoints/workload/handler.go";
  const sdsPath = "pkg/agent/endpoints/sdsv3/handler.go";
  await mkdir(dirname(join(repository, workloadPath)), { recursive: true });
  await mkdir(dirname(join(repository, sdsPath)), { recursive: true });
  await writeFile(join(repository, workloadPath), establishedWorkloadExemption);
  await writeFile(join(repository, sdsPath), sdsBeforeRateLimit);
  await execute("git", ["init", "--quiet"], { cwd: repository });
  await execute("git", ["config", "user.email", "tests@example.com"], { cwd: repository });
  await execute("git", ["config", "user.name", "Tests"], { cwd: repository });
  await execute("git", ["add", "."], { cwd: repository });
  await execute("git", ["commit", "--quiet", "-m", "fixture"], { cwd: repository });
  await writeFile(join(repository, sdsPath), vulnerableSDS);
  await writeFile(input, `${JSON.stringify({
    source: { path: repository },
    change: {
      type: "diff",
      base_ref: "HEAD",
      head_ref: "WORKTREE",
      scan_mode: "changed",
      changed_files: [sdsPath],
    },
  })}\n`);

  await execute(process.execPath, [entrypoint], {
    cwd: artifact,
    env: {
      ...process.env,
      ADVERSARY_INPUT: input,
      ADVERSARY_OUTPUT: output,
      ADVERSARY_REPO: repository,
    },
  });

  const diffEnvelope = JSON.parse(await readFile(output, "utf8"));
  const selfDenial = diffEnvelope.result.findings.filter(
    (finding: { ruleId?: string }) => finding.ruleId === "go-security.rate-limit.self-denial",
  );
  assert.equal(selfDenial.length, 1);
  assert.equal(selfDenial[0].evidence[0].file, sdsPath);
});

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
