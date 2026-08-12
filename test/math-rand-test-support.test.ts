import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { createApp } from "../src/index.ts";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const ruleId = "go-security.crypto.math-rand";

test("ignores math/rand in obvious fake and generated-mock support paths", async () => {
  const result = await reviewFixture("clean");
  assert.equal(result.findings.some((item) => item.ruleId === ruleId), false);
});

test("still flags production token code whose identifiers say fake", async () => {
  const result = await reviewFixture("vulnerable");
  const finding = result.findings.find((item) => item.ruleId === ruleId);
  assert.ok(finding);
  assert.equal(finding.evidence.length, 1);
  assert.match(finding.evidence[0]!.location?.file ?? "", /token\.go$/);
});

async function reviewFixture(name: string) {
  return createApp().run({
    input: { source: { path: join(projectRoot, "fixtures", "math-rand-test-support", name) } },
    includeRawObservations: true,
  });
}
