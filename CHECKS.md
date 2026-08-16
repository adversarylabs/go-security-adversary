# Checks — what go/security detects

This file is the **public audit list** of detectors. If a rule id appears here, it is part of the product surface: it should fire on a vulnerable pattern, stay quiet on the documented clean case, and produce file:line evidence.

Runtime source of truth: [`src/domain.ts`](src/domain.ts).  
Regression entry: [`test/p0-catalog.test.ts`](test/p0-catalog.test.ts) (P0 subset) and graded fixture snapshots.

**Scope:** non-test `*.go` files only (`*_test.go` skipped).

---

## Critical

### `go-security.tls-verification`

| | |
| --- | --- |
| **What** | TLS config sets `InsecureSkipVerify: true` |
| **Why** | Encryption without peer auth enables MITM |
| **Looks for** | `InsecureSkipVerify: true` in source |
| **Stays quiet when** | Field absent or false; verification is real |
| **Fixture** | `fixtures/p0-tls/` |
| **Remediation** | Remove skip-verify; set roots / `ServerName` |

> Catalog name `go-security.tls.insecure-skip-verify` maps to this rule. Findings use `go-security.tls-verification`.

### `go-security.sql.string-concat`

| | |
| --- | --- |
| **What** | SQL built with `fmt.Sprintf` or string concatenation into Query/Exec APIs |
| **Why** | Classic SQL injection |
| **Looks for** | `Query` / `Exec` / `*Context` with `fmt.Sprintf` or `"`…`+` style assembly |
| **Stays quiet when** | Bound parameters only (`Query("… $1", id)`) |
| **Fixture** | `fixtures/p0-sql/` |
| **Remediation** | Parameterized queries only |

### `go-security.cmd.shell`

| | |
| --- | --- |
| **What** | Shell invoked as `sh`/`bash` with `-c` |
| **Why** | Command injection when input reaches the shell string |
| **Looks for** | `exec.Command` / `CommandContext("sh"|"bash", "-c", …)` |
| **Stays quiet when** | Argv form without a shell |
| **Fixture** | `fixtures/p0-shell/` |
| **Remediation** | `exec.Command` with argv slice; never shell untrusted input |

### `go-security.crypto.hardcoded-key`

| | |
| --- | --- |
| **What** | Hardcoded key material at cipher construction |
| **Why** | Keys in source/binary are extractable |
| **Looks for** | `aes.NewCipher([]byte{…})` / similar literal key bytes near cipher APIs |
| **Stays quiet when** | Key from env/KMS/caller-provided buffer (no key literal) |
| **Fixture** | `fixtures/p0-crypto-hardcoded-key/` |
| **Remediation** | Load keys from a secret manager / KMS |

---

## High

### `go-security.pkg.signature-bypass`

| | |
| --- | --- |
| **What** | A global package-manager flag disables signature verification |
| **Why** | Repo and package signatures are the trust boundary for installed artifacts |
| **Looks for** | Live `--no-gpg-checks`, `--nogpgcheck`, `--nosignature`, or `--allow-unauthenticated` in a subprocess invocation or argument/flag builder in non-test Go |
| **Stays quiet when** | The flag is only in a comment or validation/blocklist table; the code uses a narrower local-file allowance such as `--allow-unsigned-rpm`; or a repo-scoped `gpgcheck=0` is not one of these global flags |
| **Remediation** | Keep global checks enabled; import the signing key or scope a bypass to one trusted local repository |

### `go-security.jwt-validation`

| | |
| --- | --- |
| **What** | JWT parse without an explicit accepted-algorithm constraint |
| **Why** | Algorithm confusion / incomplete verification |
| **Looks for** | `jwt.Parse` / `ParseWithClaims` without `WithValidMethods` / `ValidMethods` nearby |
| **Stays quiet when** | Parser options bind allowed algs |
| **Remediation** | Allow only intended algorithms; validate iss/aud/exp |

### `go-security.secret-logging`

| | |
| --- | --- |
| **What** | Logs include token / password / authorization / secret-like fields |
| **Why** | Logs are widely retained and shared |
| **Looks for** | `log` / `slog` / `logger` calls whose arguments mention those words |
| **Stays quiet when** | No credential-shaped fields in log args |
| **Remediation** | Log non-secret ids only; never raw secrets |

### `go-security.secret-on-argv`

| | |
| --- | --- |
| **What** | Secret-like flags/values on subprocess argv |
| **Why** | Visible via `ps`, audit logs, crash reports |
| **Looks for** | `--token` / `--password` / `--secret` / similar near `exec.Command` |
| **Stays quiet when** | Secrets via env / files / stdin |
| **Remediation** | Do not put secrets on argv |

### `go-security.token-in-url`

| | |
| --- | --- |
| **What** | Credentials embedded in a URL authority/path, or a secret-bearing HTTP query exposed through request errors/logging |
| **Why** | URLs land in proxy logs, remotes, error dumps |
| **Looks for** | `http(s)://…token…@` / user:pass@, plus secret-like `url.Values` written to `RawQuery`, sent by `net/http`, and returned/wrapped/logged through the request URL or HTTP error |
| **Stays quiet when** | Auth via headers or credential helpers |
| **Remediation** | Put credentials in authorization headers; never put long-lived secrets in URLs |

### `go-security.credential-file-mode`

| | |
| --- | --- |
| **What** | Credential-related writes with group/world-readable modes |
| **Why** | Local multi-user / CI host leakage |
| **Looks for** | `WriteFile` with permissive mode near credential-ish context |
| **Stays quiet when** | Mode `0600` / owner-only |
| **Remediation** | Write secrets as `0o600` |

### `go-security.secret-command-output`

| | |
| --- | --- |
| **What** | Printing raw output from secret-bearing CLI tools |
| **Why** | Secret CLIs can echo material to stdout/stderr |
| **Looks for** | `CombinedOutput` / `Output` / print of tool output near doppler/aws/gcloud/vault/kubectl secret flows |
| **Stays quiet when** | Sanitized errors only |
| **Remediation** | Never print raw secret-tool output |

### `go-security.path.symlink-escape`

| | |
| --- | --- |
| **What** | `os.Lstat` plus a `ModeSymlink` check is the only symlink gate before a mount or open |
| **Why** | `Lstat` reports on the last component. An intermediate symlink can redirect the later operation outside the intended root |
| **Looks for** | Non-test Go that calls `os.Lstat`, tests `os.ModeSymlink`, and then `mount` / `os.Open` / `ReadFile` / `Create` / `http.ServeFile` the path |
| **Stays quiet when** | Every component is inspected (`range` + `strings.Split` / `filepath.Split`); `O_NOFOLLOW` in that walk; `openat2` / `RESOLVE_BENEATH`; full-path `EvalSymlinks` plus containment (`IsSubPath` / `HasPrefix` / `IsLocal`); tests |
| **Deliberate false negatives** | Cross-function Lstat vs mount; syscall names not listed; symlink rejection that does not mention `ModeSymlink` |
| **Public grounding** | [fluid-cloudnative/fluid#6159](https://github.com/fluid-cloudnative/fluid/pull/6159) — `subPath "evil"` rejected, `"evil/inner"` escaped |
| **Fixture** | `fixtures/p0-symlink-escape/` |
| **Remediation** | Reject every symlink component, or open each component with `O_NOFOLLOW` / `openat2 RESOLVE_BENEATH` |

### `go-security.path.traversal`

| | |
| --- | --- |
| **What** | `filepath.Join` / `path.Join` of dynamic segments **opened** without root confinement |
| **Why** | `../` escapes intended directories |
| **Looks for** | Join of non-literal segments used with `os.Open` / `ReadFile` / `Create` / etc., without `filepath.IsLocal`, Clean+HasPrefix, securejoin, or `os.Root` |
| **Stays quiet when** | Bare internal joins with no open; or confinement present |
| **Fixture** | `fixtures/p0-path/` |
| **Remediation** | `filepath.IsLocal`, securejoin, or `os.Root` |

### `go-security.archive.zip-slip`

| | |
| --- | --- |
| **What** | Zip/tar entry names joined and written without confinement |
| **Why** | Zip-slip arbitrary file write |
| **Looks for** | `zip.OpenReader` / tar reader + join on `.Name` + create/write without IsLocal/securejoin |
| **Stays quiet when** | Entry names validated with `filepath.IsLocal` (or equivalent) before write |
| **Fixture** | `fixtures/p0-zip/` |
| **Remediation** | Reject non-local entry paths before extract |

### `go-security.crypto.math-rand`

| | |
| --- | --- |
| **What** | `math/rand` used where security-sensitive tokens/keys/nonces/sessions are nearby |
| **Why** | Predictable PRNG |
| **Looks for** | `rand.Intn` / `Read` / etc. with `math/rand` import and security-ish identifiers in file |
| **Stays quiet when** | `crypto/rand` for secrets; plain math/rand for non-security sampling without secret context |
| **Fixture** | `fixtures/p0-crypto-math-rand/` |
| **Remediation** | `crypto/rand` for all security-sensitive randomness |

### `go-security.crypto.static-nonce`

| | |
| --- | --- |
| **What** | Static or zeroed nonce/IV near AEAD/stream use |
| **Why** | Nonce reuse breaks GCM/CTR |
| **Looks for** | `nonce`/`iv` assigned via `make([]byte, N)` zeros or `{0…}` near seal/cipher use |
| **Stays quiet when** | Fresh `crypto/rand` fill per message (e.g. `io.ReadFull(rand.Reader, nonce)`) |
| **Fixture** | `fixtures/p0-crypto-static-nonce/` |
| **Remediation** | Unique nonce per message from `crypto/rand` |

### `go-security.pprof.exposed`

| | |
| --- | --- |
| **What** | `net/http/pprof` imported / registered with public listen patterns |
| **Why** | Memory and profile leakage |
| **Looks for** | `net/http/pprof` import (blank or named) |
| **Stays quiet when** | pprof not imported (bind to localhost is LLM/enhancement guidance) |
| **Fixture** | `fixtures/p0-pprof/` |
| **Remediation** | Localhost-only or auth-gated debug servers |

---

## Medium

### `go-security.attestation.null-subject-skip`

| | |
| --- | --- |
| **What** | A signed-attestation or statement verifier encounters a nil subject element and uses `continue` instead of rejecting the malformed statement |
| **Why** | A null subject violates the signed statement structure; verifier code should validate signed content fail-closed rather than normalize it |
| **Looks for** | A changed `continue` inside a nil guard for an element ranged from a subject collection, within an attestation/statement verification function |
| **Stays quiet when** | The nil branch returns an error; optional algorithms, annotations, or extensions are skipped; code is a parser or cleanup path rather than verification |
| **Fixture** | `fixtures/attestation-null-subject/` |
| **Remediation** | Return an explicit invalid-statement error for the nil element |

---

## Explicitly not this adversary

| Concern | Where it lives |
| --- | --- |
| HTTP timeouts, CORS, open redirect, WebSocket origin | `go/http` |
| Rows/tx lifecycle, GORM Raw concat | `go/database` |
| Provider-shaped committed secrets (AWS keys, PATs, …) | `security/secrets` |
| Concurrency bugs (WaitGroup, mutex copy, …) | `go/concurrency` |
| Generic CSRF / missing authz product design | LLM/enhancement roadmap — not static P0 here |

---

## How to extend

1. Add a rule object + detector in `src/domain.ts`.
2. Document the rule in this file (id, severity, looks for, quiet when, fixture).
3. Add `fixtures/<name>/{vulnerable,clean}` and a fail-closed test.
4. Keep confidence high only for deterministic evidence.
