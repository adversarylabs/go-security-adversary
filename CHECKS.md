# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `go-security.archive.zip-slip` | High | Zip/tar entry names joined and written without confinement |
| `go-security.attestation.null-subject-skip` | Medium | A signed-attestation or statement verifier encounters a nil subject element and uses `continue` instead of rejecting the malformed statement |
| `go-security.cmd.shell` | Critical | Shell invoked as `sh`/`bash` with `-c` |
| `go-security.cookie.auth-httponly` | High | An authentication cookie is readable by browser scripts |
| `go-security.credential-file-mode` | High | Credential-related writes with group/world-readable modes |
| `go-security.crypto.constant-time` | Medium | Webhook credential uses a variable-time comparison |
| `go-security.crypto.hardcoded-key` | Critical | Hardcoded key material at cipher construction |
| `go-security.crypto.math-rand` | High | `math/rand` used where security-sensitive tokens/keys/nonces/sessions are nearby |
| `go-security.crypto.static-nonce` | High | Static or zeroed nonce/IV near AEAD/stream use |
| `go-security.jwt-validation` | High | JWT parse without an explicit accepted-algorithm constraint |
| `go-security.path.symlink-escape` | High | `os.Lstat` plus a `ModeSymlink` check is the only symlink gate before a mount or open |
| `go-security.path.traversal` | High | `filepath.Join` / `path.Join` of dynamic segments **opened** without root confinement |
| `go-security.pkg.signature-bypass` | High | A global package-manager flag disables signature verification |
| `go-security.pprof.exposed` | High | `net/http/pprof` imported / registered with public listen patterns |
| `go-security.rate-limit.self-denial` | Medium | A changed service handler adds rate limiting without the repository's proven service-self exemption, allowing an operator limit to deny health or maintenance calls |
| `go-security.secret-command-output` | High | Printing raw output from secret-bearing CLI tools |
| `go-security.secret-logging` | High | Logs include token / password / authorization / secret-like fields |
| `go-security.secret-on-argv` | High | Secret-like flags/values on subprocess argv |
| `go-security.sql.string-concat` | Critical | SQL built with `fmt.Sprintf` or string concatenation into Query/Exec APIs |
| `go-security.tls-verification` | Critical | TLS config sets `InsecureSkipVerify: true` |
| `go-security.token-in-url` | High | Credentials embedded in a URL authority/path, or a secret-bearing HTTP query exposed through request errors/logging |

## Service-self rate-limit boundary

`go-security.rate-limit.self-denial` is deliberately evidence-gated. It requires a changed,
reachable rate-limit call on a context-bearing Go handler plus a sibling package in the same
service that already proves all three parts of the policy: a context-derived caller PID compared
with `os.Getpid()`, health/liveness use in the self-helper's file, and an existing rate-limit call
guarded by that self check. It reports only when the changed path lacks the equivalent direct or
centralized exemption.

It stays quiet when the self identity or health use is not proven, the limiter helper already
contains the exemption, the call is guarded directly, unreachable, stored in an uninvoked
closure, receiver-shadowed, unchanged legacy, test/generated, or comment-only. The accepted
grounding is [spiffe/spire#6724](https://github.com/spiffe/spire/pull/6724#discussion_r3335483342):
commit `97236295` passes context into the SDS limiter, exempts agent-self calls, and tests both
self bypass and non-self enforcement.
