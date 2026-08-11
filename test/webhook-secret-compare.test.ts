import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { analyzeDiscovery } from "../src/analyze.ts";
import { createApp } from "../src/index.ts";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const ruleId = "go-security.crypto.constant-time";

test("flags direct and aliased webhook credential comparisons", async () => {
  const result = await reviewFixture("vulnerable");
  const finding = result.findings.find((item) => item.ruleId === ruleId);
  assert.ok(finding);
  assert.equal(finding.evidence.length, 2);
  assert.match(finding.evidence[0]!.message ?? "", /Authorization/);
  assert.match(finding.evidence[1]!.message ?? "", /X-Webhook-Signature/);
});

test("keeps constant-time checks, empty-secret guards, and ordinary headers clean", async () => {
  const result = await reviewFixture("clean");
  assert.equal(result.findings.some((item) => item.ruleId === ruleId), false);
});

test("diff mode requires the variable-time comparison itself to change", async () => {
  const current = `package webhook
import "net/http"
type parser struct { secret string }
func (p parser) valid(r *http.Request) bool {
  return r.Header.Get("Authorization") == p.secret
}`;
  const comparisonLine = current.split("\n").findIndex((line) => line.includes("Authorization")) + 1;
  const changed = await analyzeDiscovery({
    mode: "diff",
    base: "main",
    files: [{ path: "webhook.go", current, changedLines: new Set([comparisonLine]), status: "modified" }],
  });
  assert.equal(changed.signals.some((item) => item.ruleId === ruleId), true);

  const unrelated = await analyzeDiscovery({
    mode: "diff",
    base: "main",
    files: [{ path: "webhook.go", current, changedLines: new Set([1]), status: "modified" }],
  });
  assert.equal(unrelated.signals.some((item) => item.ruleId === ruleId), false);
});

async function reviewFixture(name: string) {
  return createApp().run({
    input: { source: { path: join(projectRoot, "fixtures", "webhook-secret-compare", name) } },
    includeRawObservations: true,
  });
}
