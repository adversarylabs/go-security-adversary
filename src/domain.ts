import { contentSignal, lineSignals, positive } from "./signals.js";
import { type DomainDefinition, type SourceRevision } from "./types.js";

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
      concern: "disabled TLS peer verification",
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
      concern: "unconstrained JWT algorithm acceptance",
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
      concern: "credentials written to application logs",
      category: "security",
      severity: "high",
      confidence: "high",
      summary: (count) => `${count} logging call${count === 1 ? "" : "s"} include a token, password, or authorization value.`,
      whyItMatters: "Logs are replicated broadly and retained longer than request memory.",
      impact: "Anyone with log access may gain reusable credentials.",
      recommendation: "Remove the credential field entirely; log a stable non-secret identifier or redacted fingerprint when correlation is necessary.",
    },
    {
      id: "go-security.secret-on-argv",
      title: "A secret is passed on a subprocess argument list",
      concern: "secrets on subprocess argument lists",
      category: "security",
      severity: "high",
      confidence: "high",
      summary: (count) => `${count} subprocess invocation${count === 1 ? "" : "s"} place a token or password on argv.`,
      whyItMatters: "Process argument vectors are visible to other local users via ps, audit logs, and crash reporters.",
      impact: "Credentials can leak through process listings and shared host observability without touching application logs.",
      recommendation: "Pass secrets through environment variables, files with restricted modes, or stdin; never --token/--password on argv.",
    },
    {
      id: "go-security.token-in-url",
      title: "A credential is embedded in a URL",
      concern: "credentials embedded in URLs",
      category: "security",
      severity: "high",
      confidence: "high",
      summary: (count) => `${count} URL construction${count === 1 ? "" : "s"} embed a token or password in the authority or path.`,
      whyItMatters: "URLs are logged by proxies, VCS remotes, HTTP clients, and error messages more readily than dedicated secret fields.",
      impact: "Access tokens become durable secrets in clone URLs, redirect logs, and support dumps.",
      recommendation: "Use credential helpers, Authorization headers, or short-lived tokens that never appear in the URL string.",
    },
    {
      id: "go-security.credential-file-mode",
      title: "A credential file is written with a permissive mode",
      concern: "permissive credential file modes",
      category: "security",
      severity: "high",
      confidence: "medium",
      summary: (count) => `${count} credential write${count === 1 ? "" : "s"} use a world- or group-readable file mode.`,
      whyItMatters: "Local secret material must not be readable by other accounts on shared developer or CI hosts.",
      impact: "Other local users or compromised processes can read private keys, kubeconfigs, or API tokens from disk.",
      recommendation: "Write credential files with 0o600 (owner read/write only) and keep them outside world-writable directories.",
    },
    {
      id: "go-security.secret-command-output",
      title: "Secret-bearing command output is printed or logged",
      concern: "printed secret-bearing command output",
      category: "security",
      severity: "high",
      confidence: "medium",
      summary: (count) => `${count} path${count === 1 ? "" : "s"} print CombinedOutput or Output from a secret-bearing tool invocation.`,
      whyItMatters: "Secret manager and cloud CLI failures often echo redacted-or-not values into stderr that applications re-print.",
      impact: "Tokens and secret values can land in terminal scrollback, CI logs, and error aggregators.",
      recommendation: "Avoid printing raw tool output for secret commands; surface a sanitized error and keep secret bytes out of fmt/log arguments.",
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
        ...secretOnArgvSignals(file),
        ...tokenInUrlSignals(file),
        ...credentialFileModeSignals(file),
        ...secretCommandOutputSignals(file),
      ],
      positives: [
        ...positive(file, "go-security.jwt-algorithm-bound", /\bWithValidMethods\s*\(/, "JWT verification explicitly constrains accepted algorithms."),
        ...positive(file, "go-security.credential-mode-restricted", /WriteFile\([^)]+,\s*0o?600\b/, "Credential material is written with owner-only mode 0600."),
      ],
    };
  },
};

function secretOnArgvSignals(file: SourceRevision) {
  return lineSignals(
    file,
    "go-security.secret-on-argv",
    /(?:--token|--password|--secret|--api-key|--access-token)\b|["'](?:token|password|secret)["']\s*,/,
    () => "A secret-like flag or argument appears on a subprocess or argument list.",
  ).filter((signal) => {
    const line = file.current.split("\n")[signal.line - 1] ?? "";
    return /exec\.Command|CommandContext|Args\s*:|\.Args\s*=/.test(line) ||
      /exec\.Command|CommandContext/.test(file.current.slice(Math.max(0, file.current.indexOf(line) - 200), file.current.indexOf(line) + line.length + 80));
  });
}

function tokenInUrlSignals(file: SourceRevision) {
  return lineSignals(
    file,
    "go-security.token-in-url",
    /https?:\/\/[^\s"'`]*?(?:x-access-token|[Tt]oken|[Pp]assword|[Ss]ecret|api[_-]?key)[^\s"'`]*@|[a-z]+:\/\/[^/\s"'`]+:[^@/\s"'`]+@/i,
    () => "A URL embeds authentication material in the authority component.",
  );
}

function credentialFileModeSignals(file: SourceRevision) {
  const hasCredentialWrite = /WriteFile|WriteFileAtomic|os\.WriteFile|ioutil\.WriteFile/.test(file.current) &&
    /\b(?:token|secret|password|private[_-]?key|kubeconfig|credentials?|cert)\b/i.test(file.current);
  if (!hasCredentialWrite) return [];
  return lineSignals(
    file,
    "go-security.credential-file-mode",
    /WriteFile\([^)]*,\s*0o?[64][0-7]{2,3}\b|WriteFile\([^)]*,\s*0[64][0-7]{2,3}\b/,
    () => "Credential-related content is written with a mode that is not owner-only 0600.",
  ).filter((signal) => {
    const modeMatch = (file.current.split("\n")[signal.line - 1] ?? "").match(/0o?([0-7]{3,4})\b|0([0-7]{3,4})\b/);
    if (modeMatch === null) return false;
    const mode = Number.parseInt(modeMatch[1] ?? modeMatch[2] ?? "600", 8);
    return (mode & 0o077) !== 0;
  });
}

function secretCommandOutputSignals(file: SourceRevision) {
  const secretTool = /\b(?:doppler|aws|gcloud|vault|kubectl)\b/.test(file.current) &&
    /\b(?:secret|token|password|login|get-secret-value)\b/i.test(file.current);
  if (!secretTool) return [];
  return lineSignals(
    file,
    "go-security.secret-command-output",
    /\.(?:CombinedOutput|Output)\s*\(\)|fmt\.(?:Print|Printf|Println|Errorf)\([^)]*(?:output|out)\b/i,
    () => "Output from a secret-bearing tool invocation is captured or printed without sanitization.",
  );
}
