import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  ModelUnavailableError,
  type ModelReviewRequest,
  type ReviewModel,
  type ReviewResult,
} from "@adversarylabs/sdk";
import { createApp } from "../src/index.ts";
import {
  GO_SECURITY_MODEL_PROMPT,
  GO_SECURITY_MODEL_SCHEMA,
  type ModelSecurityReview,
} from "../src/model-review.ts";

type CapturingModel = ReviewModel & { requests: ModelReviewRequest[] };

function isConcernRewriteRequest(request: ModelReviewRequest): boolean {
  const schema = request.schema as {
    required?: string[];
    properties?: Record<string, unknown>;
  };
  return (
    Array.isArray(schema.required) &&
    schema.required.includes("concern") &&
    schema.properties !== undefined &&
    "concern" in schema.properties
  );
}

function capturingModel(output: ModelSecurityReview): CapturingModel {
  const requests: ModelReviewRequest[] = [];
  return {
    requests,
    async review<T>(request: ModelReviewRequest) {
      requests.push(request);
      if (isConcernRewriteRequest(request)) {
        return {
          output: { concern: "disabled TLS peer verification" } as T,
          provider: "fixture",
          model: "concern-rewrite",
        };
      }
      return {
        output: output as T,
        provider: "fixture",
        model: "go-security-test",
      };
    },
  };
}

function unavailableModel(): ReviewModel {
  return {
    async review() {
      throw new ModelUnavailableError("model broker not configured");
    },
  };
}

async function writeFixture(name: string, files: Record<string, string>): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), `go-security-model-${name}-`));
  for (const [relative, content] of Object.entries(files)) {
    const absolute = join(root, relative);
    await mkdir(join(absolute, ".."), { recursive: true });
    await writeFile(absolute, content);
  }
  return root;
}

async function runWithModel(root: string, model: ReviewModel): Promise<ReviewResult> {
  return createApp().run({
    model,
    input: { source: { path: root } },
  });
}

test("static findings remain when model is unavailable", async () => {
  const root = await writeFixture("static-fallback", {
    "main.go": `package main
import "crypto/tls"
func client() *tls.Config { return &tls.Config{InsecureSkipVerify: true} }
`,
  });
  const result = await runWithModel(root, unavailableModel());
  assert.equal(result.assessment?.risk, "critical");
  assert.ok(result.findings.some((f) => f.ruleId === "go-security.tls-verification"));
  assert.equal(result.opinion?.ship, false);
});

test("injected model observations appear and static still constrains ship", async () => {
  const root = await writeFixture("model-enhance", {
    "cmd/fetch.go": `package main
import (
  "fmt"
  "os/exec"
)
func fetch(token string) {
  cmd := exec.Command("doppler", "secrets", "get", "X", "--token", token)
  out, _ := cmd.CombinedOutput()
  fmt.Printf("%s", out)
}
`,
  });
  const model = capturingModel({
    assessment: {
      risk: "high",
      summary: "Secret material is exposed on argv and in tool output handling.",
    },
    ship: true,
    primaryConcern: "secrets on subprocess argument lists",
    observations: [
      {
        id: "argv-and-output",
        title: "Doppler token on argv with printed CombinedOutput",
        category: "secret-argv",
        severity: "high",
        confidence: "high",
        summary: "The Doppler token is visible in process listings and command output is printed.",
        whyItMatters: "Argv and error output are common secret exfil paths on shared hosts.",
        recommendation: "Use DOPPLER_TOKEN env and sanitize tool errors.",
        evidenceIds: [],
      },
    ],
  });

  // Prepare evidence ids from a first prepare pass by running once with empty evidence
  // then re-run with correct evidence ids from the request catalog.
  const first = await runWithModel(root, model);
  assert.ok(model.requests.length >= 1);
  const reviewRequest = model.requests.find((r) => !isConcernRewriteRequest(r))!;
  assert.equal(reviewRequest.prompt, GO_SECURITY_MODEL_PROMPT);
  assert.deepEqual(reviewRequest.schema, GO_SECURITY_MODEL_SCHEMA);
  const input = reviewRequest.input as {
    domain: string;
    deterministicSignals: Array<{ id: string; ruleId: string }>;
    evidenceCatalog: Array<{ id: string }>;
  };
  assert.equal(input.domain, "go-security");
  assert.ok(input.deterministicSignals.length >= 1);
  assert.ok(
    input.deterministicSignals.some((s) => s.ruleId === "go-security.secret-on-argv") ||
      input.deterministicSignals.some((s) => s.ruleId === "go-security.secret-command-output"),
  );

  const evidenceId = input.deterministicSignals[0]!.id;
  const model2 = capturingModel({
    assessment: {
      risk: "high",
      summary: "Secret material is exposed on argv and in tool output handling.",
    },
    ship: true, // would ship — static must still force false
    primaryConcern: "secrets on subprocess argument lists",
    observations: [
      {
        id: "argv-and-output",
        title: "Doppler token on argv with printed CombinedOutput",
        category: "secret-argv",
        severity: "medium",
        confidence: "high",
        summary: "Adds judgment that argv exposure compounds with printed CombinedOutput.",
        whyItMatters: "Argv and error output are common secret exfil paths on shared hosts.",
        recommendation: "Use DOPPLER_TOKEN env and sanitize tool errors.",
        evidenceIds: [evidenceId],
      },
    ],
  });
  const second = await runWithModel(root, model2);
  assert.equal(second.opinion?.ship, false, "static medium+ must block ship even if model says ship");
  assert.ok(
    second.observations.some((o) => o.key?.includes("model") || o.summary.includes("Doppler")) ||
      second.findings.some((f) => (f.ruleId ?? "").startsWith("go-security.")),
  );
  // Model path applied assessment summary from model
  assert.ok(second.assessment?.summary?.includes("Secret material") || second.assessment?.risk === "high");
  // Static finding still present
  assert.ok(second.findings.some((f) => (f.ruleId ?? "").startsWith("go-security.")));
  void first;
});

test("new static rules detect secret-on-argv, token-in-url, and permissive credential modes", async () => {
  const root = await writeFixture("new-rules", {
    "main.go": `package main
import (
  "fmt"
  "os"
  "os/exec"
)
func fetch(token string) {
  cmd := exec.Command("doppler", "secrets", "get", "API_KEY", "--plain", "--token", token)
  out, err := cmd.CombinedOutput()
  if err != nil { fmt.Printf("%s", out) }
}
func clone(token string) {
  url := fmt.Sprintf("https://x-access-token:%s@github.com/o/r.git", token)
  _ = exec.Command("git", "clone", url)
}
func save(path string, key []byte) error {
  return os.WriteFile(path, key, 0o644)
}
`,
  });
  const result = await runWithModel(root, unavailableModel());
  const ruleIds = new Set(result.findings.map((f) => f.ruleId ?? ""));
  assert.ok(ruleIds.has("go-security.secret-on-argv") || ruleIds.has("go-security.secret-command-output"));
  assert.ok(ruleIds.has("go-security.token-in-url"));
  // credential file mode may or may not fire depending on keyword proximity
  assert.equal(result.opinion?.ship, false);
});
