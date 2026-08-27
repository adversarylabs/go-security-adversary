import { contentSignal, lineSignals, positive } from "./signals.js";
import { type DomainDefinition, type SourceRevision } from "./types.js";

export const domain: DomainDefinition = {
  // Catalog / package identity uses domain/name taxonomy.
  name: "go/security",
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
      summary: (count) => `${count} URL construction${count === 1 ? "" : "s"} expose a token or password through the URL.`,
      whyItMatters: "URLs are logged by proxies, VCS remotes, HTTP clients, and error messages more readily than dedicated secret fields.",
      impact: "Access tokens become durable secrets in clone URLs, HTTP errors, request logs, and support dumps.",
      recommendation: "Use credential helpers or Authorization headers; keep secrets out of URL authority, path, and query components.",
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

    {
      id: "go-security.sql.string-concat",
      title: "SQL built via string concatenation",
      concern: "SQL injection via string formatting",
      category: "security",
      severity: "critical",
      confidence: "high",
      summary: (count) => `${count} SQL construction${count === 1 ? "" : "s"} use string formatting/concatenation.`,
      whyItMatters: "User-controlled fragments in SQL strings enable injection.",
      impact: "Attackers can read or modify database contents.",
      recommendation: "Use parameterized queries or bound arguments only.",
    },
    {
      id: "go-security.cmd.shell",
      title: "Shell invoked with concatenated input",
      concern: "command injection via shell",
      category: "security",
      severity: "critical",
      confidence: "high",
      summary: (count) => `${count} shell invocation${count === 1 ? "" : "s"} risk command injection.`,
      whyItMatters: "bash -c / sh -c with untrusted input enables arbitrary command execution.",
      impact: "Remote code execution on the host.",
      recommendation: "Use exec.Command with argv arrays; never pass user input to a shell.",
    },
    {
      id: "go-security.path.traversal",
      title: "Path join with user input without confinement",
      concern: "path traversal",
      category: "security",
      severity: "high",
      confidence: "medium",
      summary: (count) => `${count} path construction${count === 1 ? "" : "s"} may allow traversal.`,
      whyItMatters: "Unconfined joins of user path segments can escape intended directories.",
      impact: "Unauthorized file read or write outside the intended root.",
      recommendation: "Use filepath.IsLocal, Clean+prefix checks, securejoin, or os.Root.",
    },
    {
      id: "go-security.archive.zip-slip",
      title: "Archive extraction without path confinement",
      concern: "zip slip",
      category: "security",
      severity: "high",
      confidence: "high",
      summary: (count) => `${count} archive extraction path${count === 1 ? "" : "s"} lack confinement checks.`,
      whyItMatters: "Archive entries with ../ can escape the destination directory.",
      impact: "Arbitrary file overwrite during extraction.",
      recommendation: "Reject paths that escape the destination (filepath.IsLocal / securejoin).",
    },
    {
      id: "go-security.crypto.math-rand",
      title: "math/rand used for security-sensitive values",
      concern: "insecure randomness",
      category: "security",
      severity: "high",
      confidence: "high",
      summary: (count) => `${count} use${count === 1 ? "" : "s"} of math/rand for security-sensitive material.`,
      whyItMatters: "math/rand is predictable and unsuitable for tokens or keys.",
      impact: "Attackers can predict session tokens or nonces.",
      recommendation: "Use crypto/rand for all security-sensitive randomness.",
    },
    {
      id: "go-security.crypto.hardcoded-key",
      title: "Hardcoded cryptographic key material",
      concern: "hardcoded keys",
      category: "security",
      severity: "critical",
      confidence: "high",
      summary: (count) => `${count} hardcoded key-like constant${count === 1 ? "" : "s"} used with crypto APIs.`,
      whyItMatters: "Embedded keys are extractable from binaries and repositories.",
      impact: "Anyone with the binary can decrypt or forge messages.",
      recommendation: "Load keys from a secret manager or KMS; never embed production keys.",
    },
    {
      id: "go-security.crypto.static-nonce",
      title: "Static or zero nonce/IV with AEAD/stream cipher",
      concern: "nonce reuse",
      category: "security",
      severity: "high",
      confidence: "high",
      summary: (count) => `${count} static nonce/IV pattern${count === 1 ? "" : "s"} near AEAD or stream cipher use.`,
      whyItMatters: "Nonce reuse with GCM/CTR breaks confidentiality and authentication.",
      impact: "Attackers can recover plaintexts or forge ciphertexts.",
      recommendation: "Generate a unique nonce per message with crypto/rand.",
    },
    {
      id: "go-security.pprof.exposed",
      title: "pprof registered on a public HTTP server",
      concern: "debug endpoints exposed",
      category: "security",
      severity: "high",
      confidence: "high",
      summary: (count) => `${count} pprof registration${count === 1 ? "" : "s"} appear beside public ListenAndServe.`,
      whyItMatters: "pprof leaks process memory and profiles to remote callers.",
      impact: "Attackers can extract secrets and reverse engineer internals.",
      recommendation: "Bind pprof to localhost or protect it with authentication and network policy.",
    },
    {
      id: "go-security.attestation.null-subject-skip",
      title: "A signed attestation verifier skips a null subject",
      concern: "malformed signed attestation subjects accepted by verifier logic",
      category: "security",
      severity: "medium",
      confidence: "high",
      summary: (count) =>
        `${count} signed-attestation verification loop${count === 1 ? "" : "s"} skip null subject entries.`,
      whyItMatters:
        "A null element violates the signed statement structure and must not be normalized away during verification.",
      impact:
        "Verifier behavior diverges from the attestation schema and may process a malformed statement when another subject matches.",
      recommendation: "Return an explicit invalid-statement error when a subject element is nil.",
    },
    {
      id: "go-security.rate-limit.self-denial",
      title: "A security rate limit can deny the service's own calls",
      concern: "rate limiting applied without the established service-self exemption",
      category: "security",
      severity: "medium",
      confidence: "high",
      summary: (count) =>
        `${count} changed rate-limit path${count === 1 ? "" : "s"} omit the service's established self-caller exemption.`,
      whyItMatters:
        "A defensive control must not deny the service's own authenticated health or maintenance traffic when the repository already distinguishes those calls.",
      impact:
        "An operator-configured limit can reject service-owned calls, fail health checks, and mark an otherwise healthy service unavailable.",
      recommendation:
        "Pass the request context into the rate-limit boundary and bypass the limiter only when the repository's proven self-caller identity check matches; keep enforcement tests for non-self callers.",
    },
    {
      id: "go-security.crypto.constant-time",
      title: "Webhook credential uses a variable-time comparison",
      concern: "variable-time comparison of an attacker-supplied webhook credential",
      category: "security",
      severity: "medium",
      confidence: "high",
      summary: (count) =>
        `${count} webhook credential comparison${count === 1 ? "" : "s"} use == or != against a configured secret.`,
      whyItMatters:
        "Authentication and signature values supplied by a remote caller should not be compared with operators that may reveal matching-prefix information through timing.",
      impact:
        "An attacker able to make repeated requests and measure response time may recover a long-lived webhook credential incrementally.",
      recommendation:
        "Use crypto/subtle.ConstantTimeCompare for shared-secret headers or hmac.Equal for message authentication codes.",
    },
    {
      id: "go-security.cookie.auth-httponly",
      title: "An authentication cookie is readable by browser scripts",
      concern: "authentication and session cookies emitted without HttpOnly",
      category: "security",
      severity: "high",
      confidence: "high",
      summary: (count) =>
        `${count} authentication cookie${count === 1 ? " is" : "s are"} emitted without HttpOnly protection.`,
      whyItMatters:
        "Authentication cookies contain reusable credentials and normally have no reason to be visible to browser JavaScript.",
      impact:
        "A script running in the origin, including one introduced through XSS, can steal the cookie and replay the user's session.",
      recommendation:
        "Set HttpOnly: true on session and authentication cookies, and move any legitimate browser-readable state into a separate non-credential cookie.",
    },
    {
      id: "go-security.path.symlink-escape",
      title: "A path is confined only by a final-component symlink check",
      concern: "intermediate symlink escape before mount or open",
      category: "security",
      severity: "high",
      confidence: "high",
      summary: (count) =>
        `${count} path${count === 1 ? " uses" : "s use"} os.Lstat as the only symlink gate before a mount or open.`,
      whyItMatters:
        "os.Lstat reports on the last component. An earlier symlink can redirect the later mount or open outside the intended root.",
      impact:
        "A crafted subpath such as evil/inner can publish or read a host path outside the guarded tree even when the final name is not a symlink.",
      recommendation:
        "Reject every symlink component, or open each component with O_NOFOLLOW / openat2 RESOLVE_BENEATH, then operate on the resulting descriptor.",
    },
    {
      id: "go-security.pkg.signature-bypass",
      title: "Package-manager signature verification is globally disabled",
      concern: "global package-manager signature verification bypass",
      category: "security",
      severity: "high",
      confidence: "high",
      summary: (count) =>
        `${count} package-manager invocation${count === 1 ? "" : "s"} disable signature verification globally.`,
      whyItMatters:
        "Repository and package signatures are the trust boundary that prevents a build host from installing substituted artifacts.",
      impact:
        "A compromised mirror, cache, or local file can be installed as if it were a verified package, including when the flag was added only to accept one unsigned local RPM.",
      recommendation:
        "Keep global GPG checks enabled. Import the signing key or scope a verification exception to one trusted local repository instead of --no-gpg-checks, --nogpgcheck, --nosignature, or --allow-unauthenticated.",
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
        ...lineSignals(file, "go-security.sql.string-concat", /(?:Query|Exec|QueryContext|ExecContext)\s*\(\s*(?:fmt\.Sprintf|["'`].*(?:\+|fmt\.))/, () => "SQL appears constructed via string formatting or concatenation."),
        ...lineSignals(file, "go-security.cmd.shell", /exec\.Command(?:Context)?\(\s*["'](?:ba)?sh["']\s*,\s*["']-c["']/, () => "A shell is invoked with -c, which is dangerous with untrusted input."),
        ...pathTraversalSignals(file),
        ...zipSlipSignals(file),
        ...mathRandSignals(file),
        ...lineSignals(file, "go-security.crypto.hardcoded-key", /(?:aes|cipher)\.(?:NewCipher|NewGCM)\(\s*\[\]byte\{/, () => "Hardcoded key material appears near a cipher constructor."),
        ...lineSignals(file, "go-security.crypto.static-nonce", /(?:nonce|iv)\s*(?::=|=)\s*(?:make\(\[\]byte,\s*\d+\)|\[\]byte\{0)/i, () => "Static or zeroed nonce/IV pattern near cryptographic use."),
        ...lineSignals(file, "go-security.pprof.exposed", /net\/http\/pprof|_\s+"net\/http\/pprof"/, () => "pprof is imported; ensure it is not exposed on a public listener."),
        ...packageSignatureBypassSignals(file),
      ],
      positives: [
        ...positive(file, "go-security.jwt-algorithm-bound", /\bWithValidMethods\s*\(/, "JWT verification explicitly constrains accepted algorithms."),
        ...positive(file, "go-security.credential-mode-restricted", /WriteFile\([^)]+,\s*0o?600\b/, "Credential material is written with owner-only mode 0600."),
      ],
    };
  },
};

function mathRandSignals(file: SourceRevision) {
  if (isObviousTestSupportPath(file.path)) return [];
  return lineSignals(
    file,
    "go-security.crypto.math-rand",
    /\brand\.(?:Intn|Read|Float64|Int63)\b/,
    () => "math/rand used; ensure this is not security-sensitive (prefer crypto/rand).",
  ).filter(() => /\bmath\/rand\b/.test(file.current) && /token|secret|password|nonce|session|key/i.test(file.current));
}

const PACKAGE_SIGNATURE_BYPASS =
  /--(?:no-gpg-checks|nogpgcheck|nosignature|allow-unauthenticated)\b/;

function packageSignatureBypassSignals(file: SourceRevision) {
  return lineSignals(
    file,
    "go-security.pkg.signature-bypass",
    PACKAGE_SIGNATURE_BYPASS,
    (match) => `This package-manager invocation disables signature verification (${match[0]}).`,
  ).filter((signal) => {
    const code = signal.snippet.replace(/\/\/.*$/, "").replace(/\/\*.*$/, "");
    if (!PACKAGE_SIGNATURE_BYPASS.test(code)) return false;
    return /\bexec\.Command(?:Context)?\s*\(/.test(code) ||
      /\bappend\s*\(\s*[A-Za-z_]\w*(?:args?|flags?|options?)\b/i.test(code) ||
      /\b[A-Za-z_]\w*(?:args?|flags?|options?)\s*:?=\s*\[\]string\s*\{/i.test(code);
  });
}

function isObviousTestSupportPath(path: string): boolean {
  const normalized = path.replaceAll("\\", "/").toLowerCase();
  const parts = normalized.split("/");
  if (parts.some((part) => /^(?:fake|fakes|fixture|fixtures|mock|mocks|testdata)$/.test(part))) {
    return true;
  }
  const filename = parts.at(-1) ?? "";
  return /^(?:mock|fake)_.+\.go$/.test(filename) || /\.(?:mock|fake)\.go$/.test(filename);
}

/**
 * Catalog P0 path.traversal — only when a Join of non-literal segments is opened
 * (os.Open/ReadFile/…) without a confinement guard (IsLocal, HasPrefix+Clean,
 * securejoin, os.OpenRoot / os.Root). Bare filepath.Join for internal paths stays quiet.
 */
function pathTraversalSignals(file: SourceRevision) {
  if (file.path.endsWith("_test.go")) return [];
  const source = file.current;
  if (!/(?:filepath|path)\.Join\s*\(/.test(source)) return [];

  const hasConfinement =
    /filepath\.IsLocal\s*\(/.test(source) ||
    /securejoin\.(?:SecureJoin|SecureJoinVFS)\s*\(/.test(source) ||
    /\bos\.(?:OpenRoot|Root)\b/.test(source) ||
    // Clean + HasPrefix / strings.HasPrefix confinement pattern
    (/filepath\.Clean\s*\(/.test(source) &&
      /(?:strings\.HasPrefix|filepath\.HasPrefix)\s*\(/.test(source));

  if (hasConfinement) return [];

  // Join used directly as open/read/create path argument
  const direct = lineSignals(
    file,
    "go-security.path.traversal",
    /(?:os\.(?:Open|OpenFile|ReadFile|WriteFile|Create|MkdirAll|Remove|RemoveAll|Stat|Lstat)|ioutil\.(?:ReadFile|WriteFile)|http\.ServeFile)\s*\(\s*(?:filepath|path)\.Join\s*\(/,
    () => "Path join of untrusted segments is opened without root confinement.",
  );
  if (direct.length > 0) return direct;

  // Multi-step: p := filepath.Join(base, dynamic); os.Open(p) — second+ Join args not only string literals
  const joinAssign =
    /\b([A-Za-z_]\w*)\s*:?=\s*(?:filepath|path)\.Join\s*\(([^)]*)\)/g;
  const signals: ReturnType<typeof lineSignals> = [];
  let match: RegExpExecArray | null;
  while ((match = joinAssign.exec(source)) !== null) {
    const varName = match[1]!;
    const args = match[2] ?? "";
    // Require at least one non-string-literal argument (user-controlled segment)
    const hasDynamicArg = args
      .split(",")
      .map((a) => a.trim())
      .some((a) => a.length > 0 && !/^[`"']/.test(a));
    if (!hasDynamicArg) continue;
    const escaped = varName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const openRe = new RegExp(
      `\\b(?:os\\.(?:Open|OpenFile|ReadFile|WriteFile|Create|MkdirAll|Remove|RemoveAll|Stat|Lstat)|ioutil\\.(?:ReadFile|WriteFile)|http\\.ServeFile)\\s*\\(\\s*${escaped}\\b`,
    );
    if (!openRe.test(source)) continue;
    const line = source.slice(0, match.index).split("\n").length;
    signals.push({
      ruleId: "go-security.path.traversal",
      path: file.path,
      line,
      message: `Joined path "${varName}" is opened without root confinement (IsLocal/securejoin/os.Root).`,
      snippet: (match[0] ?? "").trim().slice(0, 300),
      data: { variable: varName },
    });
  }
  return signals;
}

/**
 * Catalog P0 archive.zip-slip — zip/tar entry names joined into filesystem paths
 * without IsLocal / Clean+HasPrefix / securejoin confinement.
 */
function zipSlipSignals(file: SourceRevision) {
  if (file.path.endsWith("_test.go")) return [];
  const source = file.current;
  const hasArchive =
    /\bzip\.(?:OpenReader|NewReader)\b/.test(source) ||
    /\btar\.(?:NewReader|Reader)\b/.test(source) ||
    /archive\/(?:zip|tar)/.test(source);
  if (!hasArchive) return [];

  const joinsEntry =
    /(?:filepath|path)\.Join\s*\([^)]*\.(?:Name|FileInfo\(\)\.Name)/.test(source) ||
    /(?:filepath|path)\.Join\s*\([^,]+,\s*(?:f|file|hdr|header|entry)\.Name\b/.test(source) ||
    /(?:filepath|path)\.Join\s*\([^,]+,\s*\w+\.Name\b/.test(source);

  if (!joinsEntry) {
    // Still flag OpenReader-only extraction stubs that write with entry.Name directly
    if (!/\.Name\b/.test(source)) return [];
  }

  const hasConfinement =
    /filepath\.IsLocal\s*\(/.test(source) ||
    /securejoin\.(?:SecureJoin|SecureJoinVFS)\s*\(/.test(source) ||
    (/\bfilepath\.Clean\s*\(/.test(source) &&
      /(?:strings\.HasPrefix|filepath\.HasPrefix)\s*\(/.test(source)) ||
    /\bos\.(?:OpenRoot|Root)\b/.test(source);

  if (hasConfinement) return [];

  // Require evidence of extraction write, not mere archive open for listing
  const extracts =
    /\b(?:os\.(?:OpenFile|Create|MkdirAll|WriteFile)|ioutil\.WriteFile|io\.Copy)\s*\(/.test(source) ||
    joinsEntry;
  if (!extracts) return [];

  return lineSignals(
    file,
    "go-security.archive.zip-slip",
    /zip\.(?:OpenReader|NewReader)|tar\.NewReader|(?:filepath|path)\.Join\s*\([^)]*\.Name/,
    () => "Archive entry path is joined/written without confinement (zip-slip).",
  ).slice(0, 3);
}

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
