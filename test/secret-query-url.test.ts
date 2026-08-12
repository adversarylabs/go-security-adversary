import assert from "node:assert/strict";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { analyzeDiscovery } from "../src/analyze.ts";
import { createApp } from "../src/index.ts";

const projectRoot = dirname(dirname(fileURLToPath(import.meta.url)));
const ruleId = "go-security.token-in-url";

test("flags a secret-bearing query returned through an HTTP URL error", async () => {
  const result = await reviewFixture("vulnerable");
  const finding = result.findings.find((item) => item.ruleId === ruleId);
  assert.ok(finding, JSON.stringify(result.findings, null, 2));
  assert.match(finding.evidence[0]?.message ?? "", /access_token.*HTTP query.*HTTP error err/);
  assert.equal(finding.evidence[0]?.data?.queryKey, "access_token");
});

test("keeps headers, ordinary query values, and sanitized failures clean", async () => {
  const result = await reviewFixture("clean");
  assert.equal(
    result.findings.some((item) => item.ruleId === ruleId),
    false,
    JSON.stringify(result.findings, null, 2),
  );
});

test("recognizes logged HTTP errors and direct request URL sinks", async () => {
  const current = `package client
import (
  "log"
  "net/http"
  "net/url"
)
func fetch(client *http.Client, endpoint string, clientSecret string) {
  target, _ := url.Parse(endpoint)
  query := target.Query()
  query.Add("client_secret", clientSecret)
  target.RawQuery = query.Encode()
  req, _ := http.NewRequest(http.MethodGet, target.String(), nil)
  _, err := client.Do(req)
  if err != nil { log.Printf("request %s failed: %v", req.URL, err) }
}
`;
  const analysis = await repositoryAnalysis(current);
  const signal = analysis.signals.find((item) => item.ruleId === ruleId);
  assert.ok(signal);
  assert.equal(signal.data.queryKey, "client_secret");
  assert.match(signal.message, /logged or wrapped HTTP error err/);
});

test("diff mode requires a changed query, request flow, or exposure sink", async () => {
  const current = `package client
import (
  "fmt"
  "net/http"
  "net/url"
)
func fetch(client *http.Client, endpoint string, apiKey string) error {
  target, _ := url.Parse(endpoint)
  query := target.Query()
  query.Set("api_key", apiKey)
  target.RawQuery = query.Encode()
  _, err := client.Get(target.String())
  return fmt.Errorf("fetch: %w", err)
}
`;
  const queryLine = lineContaining(current, "query.Set");
  const sinkLine = lineContaining(current, "return fmt.Errorf");
  const changedQuery = await diffAnalysis(current, queryLine);
  assert.equal(changedQuery.signals.find((item) => item.ruleId === ruleId)?.line, queryLine);

  const changedSink = await diffAnalysis(current, sinkLine);
  assert.equal(changedSink.signals.find((item) => item.ruleId === ruleId)?.line, sinkLine);

  const unrelated = await diffAnalysis(current, 1);
  assert.equal(unrelated.signals.some((item) => item.ruleId === ruleId), false);
});

async function reviewFixture(name: string) {
  return createApp().run({
    input: { source: { path: join(projectRoot, "fixtures", "secret-query-url", name) } },
    includeRawObservations: true,
  });
}

async function repositoryAnalysis(current: string) {
  return analyzeDiscovery({
    mode: "repository",
    files: [{ path: "client.go", current, changedLines: new Set(), status: "repository" }],
  });
}

async function diffAnalysis(current: string, line: number) {
  return analyzeDiscovery({
    mode: "diff",
    base: "main",
    files: [{ path: "client.go", current, changedLines: new Set([line]), status: "modified" }],
  });
}

function lineContaining(source: string, text: string): number {
  return source.split("\n").findIndex((line) => line.includes(text)) + 1;
}
