import assert from "node:assert/strict";
import test from "node:test";
import { analyzeDiscovery } from "../src/analyze.ts";
import { type SourceRevision } from "../src/types.ts";

const ruleId = "go-security.rate-limit.self-denial";

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

const safeSDS = `package sdsv3
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
func (h *Handler) rateLimit(ctx context.Context, method string, selectors []string) error {
  if h.c.RateLimiter == nil { return nil }
  if isAgent(ctx) { return nil }
  return h.c.RateLimiter.RateLimit(method, selectors)
}
func (h *Handler) StreamSecrets(ctx context.Context, selectors []string) error {
  if err := h.rateLimit(ctx, "StreamSecrets", selectors); err != nil { return err }
  return nil
}
`;

test("reports the SPIRE-shaped rate-limit path lacking the established self exemption", async () => {
  const callLine = lineOf(vulnerableSDS, "if err := h.rateLimit");
  const files = [
    repository("pkg/agent/endpoints/workload/handler.go", establishedWorkloadExemption),
    modified(
      "pkg/agent/endpoints/sdsv3/handler.go",
      vulnerableSDS,
      vulnerableSDS.replace('  if err := h.rateLimit("StreamSecrets", selectors); err != nil { return err }\n', ""),
      [callLine],
    ),
  ];
  const analysis = await analyzeDiscovery({
    mode: "diff",
    base: "base",
    files,
  });

  const signals = analysis.signals.filter((signal) => signal.ruleId === ruleId);
  assert.equal(signals.length, 1);
  assert.equal(signals[0]!.path, "pkg/agent/endpoints/sdsv3/handler.go");
  assert.equal(signals[0]!.line, callLine);
  assert.match(signals[0]!.message, /established self-caller exemption/);
  assert.equal(signals[0]!.data.establishedPath, "pkg/agent/endpoints/workload/handler.go");
});

test("stays quiet for the accepted centralized self exemption and direct guards", async () => {
  const safe = await analyzeDiscovery({
    mode: "repository",
    files: [
      repository("pkg/agent/endpoints/workload/handler.go", establishedWorkloadExemption),
      repository("pkg/agent/endpoints/sdsv3/handler.go", safeSDS),
    ],
  });
  assert.equal(safe.signals.some((signal) => signal.ruleId === ruleId), false);

  const directlyGuarded = vulnerableSDS
    .replace('import "context"', 'import (\n  "context"\n  "os"\n  "example.test/spire/pkg/agent/api/rpccontext"\n)')
    .replace(
      "type Handler struct { c Config }",
      "type Handler struct { c Config }\nfunc isAgent(ctx context.Context) bool { return rpccontext.CallerPID(ctx) == os.Getpid() }",
    )
    .replace(
      '  if err := h.rateLimit("StreamSecrets", selectors); err != nil { return err }',
      '  if !isAgent(ctx) {\n    if err := h.rateLimit("StreamSecrets", selectors); err != nil { return err }\n  }',
    );
  const guarded = await analyzeDiscovery({
    mode: "repository",
    files: [
      repository("pkg/agent/endpoints/workload/handler.go", establishedWorkloadExemption),
      repository("pkg/agent/endpoints/sdsv3/handler.go", directlyGuarded),
    ],
  });
  assert.equal(guarded.signals.some((signal) => signal.ruleId === ruleId), false);

  const renamedContext = directlyGuarded
    .replace("StreamSecrets(ctx context.Context", "StreamSecrets(requestContext context.Context")
    .replace("if !isAgent(ctx)", "if !isAgent(requestContext)");
  const renamed = await analyzeDiscovery({
    mode: "repository",
    files: [
      repository("pkg/agent/endpoints/workload/handler.go", establishedWorkloadExemption),
      repository("pkg/agent/endpoints/sdsv3/renamed.go", renamedContext),
    ],
  });
  assert.equal(renamed.signals.some((signal) => signal.ruleId === ruleId), false);
});

test("does not trust conditional or shadowed self checks as exemptions", async () => {
  const localHelper = vulnerableSDS
    .replace('import "context"', 'import (\n  "context"\n  "os"\n  "example.test/spire/pkg/agent/api/rpccontext"\n)')
    .replace(
      "type Handler struct { c Config }",
      "type Handler struct { c Config }\nfunc isAgent(ctx context.Context) bool { return rpccontext.CallerPID(ctx) == os.Getpid() }",
    );
  const conditional = localHelper.replace(
    '  if err := h.rateLimit("StreamSecrets", selectors); err != nil { return err }',
    '  if enabled() {\n    if isAgent(ctx) { return nil }\n  }\n  if err := h.rateLimit("StreamSecrets", selectors); err != nil { return err }',
  );
  const shadowed = localHelper.replace(
    '  if err := h.rateLimit("StreamSecrets", selectors); err != nil { return err }',
    '  isAgent := func(context.Context) bool { return false }\n  if !isAgent(ctx) {\n    if err := h.rateLimit("StreamSecrets", selectors); err != nil { return err }\n  }',
  );
  const reassignedContext = localHelper.replace(
    '  if err := h.rateLimit("StreamSecrets", selectors); err != nil { return err }',
    '  ctx = context.Background()\n  if !isAgent(ctx) {\n    if err := h.rateLimit("StreamSecrets", selectors); err != nil { return err }\n  }',
  );

  for (const [name, target] of [
    ["conditional", conditional],
    ["shadowed", shadowed],
    ["reassigned-context", reassignedContext],
  ] as const) {
    const analysis = await analyzeDiscovery({
      mode: "repository",
      files: [
        repository("pkg/agent/endpoints/workload/handler.go", establishedWorkloadExemption),
        repository(`pkg/agent/endpoints/sdsv3/${name}.go`, target),
      ],
    });
    assert.equal(analysis.signals.filter((signal) => signal.ruleId === ruleId).length, 1, name);
  }
});

test("requires proven self identity, health use, binding, and reachable execution", async () => {
  const noIdentity = establishedWorkloadExemption.replace(
    "return rpccontext.CallerPID(ctx) == os.Getpid()",
    "return configured()",
  );
  const deadIdentity = establishedWorkloadExemption.replace(
    "return rpccontext.CallerPID(ctx) == os.Getpid()",
    "if false { return rpccontext.CallerPID(ctx) == os.Getpid() }\n  return false",
  );
  const noHealth = establishedWorkloadExemption.replace("health check", "periodic caller");
  const dead = vulnerableSDS.replace(
    '  if err := h.rateLimit("StreamSecrets", selectors); err != nil { return err }',
    '  if false {\n    if err := h.rateLimit("StreamSecrets", selectors); err != nil { return err }\n  }',
  );
  const storedClosure = vulnerableSDS.replace(
    '  if err := h.rateLimit("StreamSecrets", selectors); err != nil { return err }',
    '  later := func() { _ = h.rateLimit("StreamSecrets", selectors) }\n  _ = later',
  );
  const shadowedReceiver = vulnerableSDS.replace(
    '  if err := h.rateLimit("StreamSecrets", selectors); err != nil { return err }',
    '  h := otherHandler()\n  if err := h.rateLimit("StreamSecrets", selectors); err != nil { return err }',
  );
  const reassignedReceiver = vulnerableSDS.replace(
    '  if err := h.rateLimit("StreamSecrets", selectors); err != nil { return err }',
    '  h = otherHandler()\n  if err := h.rateLimit("StreamSecrets", selectors); err != nil { return err }',
  );

  for (const [name, sibling, target] of [
    ["unproven identity", noIdentity, vulnerableSDS],
    ["dead identity comparison", deadIdentity, vulnerableSDS],
    ["no health use", noHealth, vulnerableSDS],
    ["dead call", establishedWorkloadExemption, dead],
    ["stored closure", establishedWorkloadExemption, storedClosure],
    ["receiver shadow", establishedWorkloadExemption, shadowedReceiver],
    ["receiver reassignment", establishedWorkloadExemption, reassignedReceiver],
  ] as const) {
    const analysis = await analyzeDiscovery({
      mode: "repository",
      files: [
        repository("pkg/agent/endpoints/workload/handler.go", sibling),
        repository(`pkg/agent/endpoints/sdsv3/${name.replaceAll(" ", "-")}.go`, target),
      ],
    });
    assert.equal(analysis.signals.some((signal) => signal.ruleId === ruleId), false, name);
  }
});

test("requires a changed semantic relationship and ignores comment-only edits", async () => {
  const legacyMethod = `func (h *Handler) LegacySecrets(ctx context.Context, selectors []string) error {
  if err := h.rateLimit("LegacySecrets", selectors); err != nil { return err }
  return nil
}
`;
  const currentWithLegacy = vulnerableSDS.replace(
    "func (h *Handler) StreamSecrets",
    `${legacyMethod}func (h *Handler) StreamSecrets`,
  );
  const previousWithLegacy = currentWithLegacy.replace(
    `func (h *Handler) StreamSecrets(ctx context.Context, selectors []string) error {
  if err := h.rateLimit("StreamSecrets", selectors); err != nil { return err }
  return nil
}
`,
    "",
  );
  const addedBesideLegacy = await analyzeDiscovery({
    mode: "diff",
    base: "base",
    files: [
      repository("pkg/agent/endpoints/workload/handler.go", establishedWorkloadExemption),
      modified(
        "pkg/agent/endpoints/sdsv3/handler.go",
        currentWithLegacy,
        previousWithLegacy,
        [lineOf(currentWithLegacy, 'if err := h.rateLimit("StreamSecrets"')],
      ),
    ],
  });
  const addedSignals = addedBesideLegacy.signals.filter((signal) => signal.ruleId === ruleId);
  assert.equal(addedSignals.length, 1);
  assert.equal(addedSignals[0]!.line, lineOf(currentWithLegacy, 'if err := h.rateLimit("StreamSecrets"'));

  const legacy = await analyzeDiscovery({
    mode: "diff",
    base: "base",
    files: [
      repository("pkg/agent/endpoints/workload/handler.go", establishedWorkloadExemption),
      modified(
        "pkg/agent/endpoints/sdsv3/handler.go",
        vulnerableSDS.replace("return nil\n}", "return nil // unrelated docs\n}"),
        vulnerableSDS,
        [lineOf(vulnerableSDS, "return nil")],
      ),
    ],
  });
  assert.equal(legacy.signals.some((signal) => signal.ruleId === ruleId), false);

  const commentOnly = await analyzeDiscovery({
    mode: "diff",
    base: "base",
    files: [
      repository("pkg/agent/endpoints/workload/handler.go", establishedWorkloadExemption),
      modified(
        "pkg/agent/endpoints/sdsv3/handler.go",
        vulnerableSDS.replace("StreamSecrets(ctx", "StreamSecrets(/* docs */ ctx"),
        vulnerableSDS,
        [lineOf(vulnerableSDS, "func (h *Handler) StreamSecrets")],
      ),
    ],
  });
  assert.equal(commentOnly.signals.some((signal) => signal.ruleId === ruleId), false);
});

function repository(path: string, current: string): SourceRevision {
  return { path, current, changedLines: new Set(), status: "repository" };
}

function modified(path: string, current: string, previous: string, changedLines: number[]): SourceRevision {
  return { path, current, previous, changedLines: new Set(changedLines), status: "modified" };
}

function lineOf(source: string, contains: string): number {
  return source.split("\n").findIndex((line) => line.includes(contains)) + 1;
}
