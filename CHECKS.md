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
| `go-security.secret-command-output` | High | Printing raw output from secret-bearing CLI tools |
| `go-security.secret-logging` | High | Logs include token / password / authorization / secret-like fields |
| `go-security.secret-on-argv` | High | Secret-like flags/values on subprocess argv |
| `go-security.sql.string-concat` | Critical | SQL built with `fmt.Sprintf` or string concatenation into Query/Exec APIs |
| `go-security.tls-verification` | Critical | TLS config sets `InsecureSkipVerify: true` |
| `go-security.tls.insecure-skip-verify` | Critical | TLS InsecureSkipVerify enabled |
| `go-security.token-in-url` | High | Credentials embedded in a URL authority/path, or a secret-bearing HTTP query exposed through request errors/logging |
