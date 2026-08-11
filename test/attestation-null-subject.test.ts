import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { analyzeDiscovery } from "../src/analyze.ts";
import { createApp } from "../src/index.ts";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const ruleId = "go-security.attestation.null-subject-skip";

test("flags a signed-attestation verifier that skips a nil subject", async () => {
  const result = await reviewFixture("vulnerable");
  const finding = result.findings.find((item) => item.ruleId === ruleId);
  assert.ok(finding);
  assert.equal(finding.evidence.length, 1);
  assert.match(finding.evidence[0]!.message ?? "", /statement\.Subject/);
});

test("stays quiet for fail-closed verification and unrelated cleanup", async () => {
  const result = await reviewFixture("clean");
  assert.equal(result.findings.some((item) => item.ruleId === ruleId), false);
});

test("diff mode points to the changed continue", async () => {
  const current = `package attestation
type Subject struct{}
type Statement struct { Subject []*Subject }
func IntotoSubjectClaimVerifier(statement Statement) error {
  for _, subject := range statement.Subject {
    if subject == nil {
      continue
    }
  }
  return nil
}`;
  const continueLine = current.split("\n").findIndex((line) => line.includes("continue")) + 1;
  const analysis = await analyzeDiscovery({
    mode: "diff",
    base: "main",
    files: [{
      path: "pkg/cosign/verifiers.go",
      current,
      changedLines: new Set([continueLine]),
      status: "modified",
    }],
  });
  const signals = analysis.signals.filter((item) => item.ruleId === ruleId);
  assert.equal(signals.length, 1);
  assert.equal(signals[0]!.line, continueLine);
});

async function reviewFixture(name: string) {
  return createApp().run({
    input: { source: { path: join(projectRoot, "fixtures", "attestation-null-subject", name) } },
    includeRawObservations: true,
  });
}
