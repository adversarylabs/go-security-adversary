import { contentSignal, lineSignals, positive } from "./signals.js";
import { type DomainDefinition } from "./types.js";

export const domain: DomainDefinition = {
  name: "go-security",
  displayName: "Go Security",
  observationKey: "go-security.analysis",
  sourceDescription: "security-relevant Go",
  includePath: (path) => path.endsWith(".go") && !path.endsWith("_test.go"),
  rules: [
    {
      id: "go-security.tls-verification",
      title: "TLS certificate verification is disabled",
      category: "security",
      severity: "critical",
      confidence: "high",
      summary: (count) => `${count} TLS configuration${count === 1 ? "" : "s"} disable peer verification.`,
      whyItMatters: "Encryption without peer authentication does not establish who receives credentials or sensitive traffic.",
      impact: "An active network attacker can impersonate the service and read or modify traffic.",
      recommendation: "Remove InsecureSkipVerify and configure the expected roots and server name; use VerifyConnection only for deliberate equivalent verification.",
    },
    {
      id: "go-security.jwt-validation",
      title: "JWT parsing does not constrain accepted algorithms",
      category: "security",
      severity: "high",
      confidence: "high",
      summary: (count) => `${count} JWT parsing path${count === 1 ? "" : "s"} accept tokens without an explicit algorithm allowlist.`,
      whyItMatters: "Token verification must bind the issuer's expected algorithm and claims to the supplied key.",
      impact: "Algorithm confusion or incomplete claim validation can allow unauthorized requests.",
      recommendation: "Use parser options that allow only the intended algorithms and validate issuer, audience, expiry, and subject semantics.",
    },
    {
      id: "go-security.secret-logging",
      title: "A credential-like value is written to logs",
      category: "security",
      severity: "high",
      confidence: "high",
      summary: (count) => `${count} logging call${count === 1 ? "" : "s"} include a token, password, or authorization value.`,
      whyItMatters: "Logs are replicated broadly and retained longer than request memory.",
      impact: "Anyone with log access may gain reusable credentials.",
      recommendation: "Remove the credential field entirely; log a stable non-secret identifier or redacted fingerprint when correlation is necessary.",
    },
  ],
  noRiskSummary: "No high-confidence trust-boundary, credential, or transport defect was found in the reviewed code.",
  approvalSummary: "I would approve the reviewed security boundaries represented by this change.",
  analyze(file) {
    const jwt = /\bjwt\.(?:Parse|ParseWithClaims)\s*\(/.test(file.current) && !/(WithValidMethods|ValidMethods)/.test(file.current)
      ? contentSignal(file, "go-security.jwt-validation", /\bjwt\.(?:Parse|ParseWithClaims)\s*\(/, "JWT parsing has no visible accepted-algorithm constraint.")
      : [];
    return {
      signals: [
        ...lineSignals(file, "go-security.tls-verification", /\bInsecureSkipVerify\s*:\s*true\b/, () => "This TLS client accepts any server certificate."),
        ...jwt,
        ...lineSignals(
          file,
          "go-security.secret-logging",
          /\b(?:slog|log|logger)\.(?:Info|Warn|Error|Debug|Printf?)\s*\([^)]*\b(?:token|password|authorization|secret)\b/i,
          () => "This log statement includes a credential-like value.",
        ),
      ],
      positives: [
        ...positive(file, "go-security.jwt-algorithm-bound", /\bWithValidMethods\s*\(/, "JWT verification explicitly constrains accepted algorithms."),
      ],
    };
  },
};
