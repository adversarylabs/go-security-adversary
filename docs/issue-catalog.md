# go/security — issue catalog

This document is the **issue catalog** for this adversary: the classes of defects we aim to find, how we detect them (static vs LLM), public pattern references, and staff priority (P0 / P1 / LLM-only / Cut).

It is documentation and roadmap for contributors — not a runtime contract. Implemented detectors live in `src/` with fixtures under `fixtures/`; the **Review verdicts** section records what ships first.

Public examples cited below illustrate bad patterns only. Do not scrape secrets from them or copy copyrighted code into fixtures.

**Catalog id:** `go/security`  
**Status:** public OSS documentation of the issue classes this adversary targets  
**Goal:** trusted, high-precision detections. Prefer missing a weak signal over a false positive.

## Mission
Go trust-boundary security: TLS, crypto, injection, authn/z, and secret handling with staff-level judgment.

## LLM strategy (required for world-class)
**Enhance:** connect weak TLS + SSRF + auth gaps into exploit paths; suppress test-only crypto.
**Discover:** authorization gaps and multi-handler auth bugs static rules miss.

### Division of labor
| Layer | Responsibility |
| --- | --- |
| **Static / structural** | Deterministic signals with line-level evidence. |
| **LLM enhancement** | Impact stories, ranking, FP suppression with context. |
| **LLM discovery** | Novel issues only with concrete evidence. |

### Trust / anti-FP rules
1. Evidence required. 2. LLM-only default medium/low. 3. One finding per remediations story. 4. When unsure, omit.

## Review verdicts (staff pass)

- **P0 implement:** `tls.insecure-skip-verify`, `sql.string-concat`, `cmd.shell`, `path.traversal`, `archive.zip-slip`, `crypto.math-rand`, `crypto.hardcoded-key`, `crypto.static-nonce`, `pprof.exposed`
- **P1:** `crypto.md5-sha1`, `auth.jwt-unverified`, `cookie.secure-flags`, `ssrf.user-url`, `deserialization.gob`, `file.perm-world`, `grpc.insecure`, `template.missing-escape`, `dir.listing`, `log.secrets`, `session.timeout`, `crypto.constant-time`
- **LLM-only:** `csrf.missing`, `authz.missing`, `rate-limit.missing`, `reflect.unsafe`
- **Cut:** `http.default-client` — duplicate of `go-http.client.no-timeout` (owned there). `cors.wildcard` — duplicate of `go-http.cors.permissive` (owned there).
- **Renamed:** `auth.jwt-none` → `auth.jwt-unverified` (golang-jwt v4+ rejects alg=none by default; the real bug class is skipped verification).

## Issue catalog

---
### 1. `go-security.tls.insecure-skip-verify` — TLS InsecureSkipVerify enabled

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | high |

**What it is.** tls.Config{InsecureSkipVerify: true} disables cert validation.

**Static detection.** AST: composite lit field true outside tests.

**LLM role.** Allow _test.go and explicit test helpers named testing only if path matches.

**False-positive guards.** Test-only files; #nosec with justification still report low.

**Public examples of the bad pattern:**
  - https://codeql.github.com/codeql-query-help/go/go-disabled-certificate-check/
  - https://github.com/google/go-containerregistry/issues/1613 — real discussion of skip-verify
  - https://gist.github.com/denji/12b3a568f092ab951456 — common insecure examples online

---
### 2. `go-security.crypto.md5-sha1` — MD5/SHA1 used for security

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** crypto/md5 or sha1 for tokens/signatures.

**Static detection.** Import + call graph heuristic vs checksum use.

**LLM role.** LLM: integrity vs security use.

**False-positive guards.** Git object hashes; non-security checksums.

**Public examples of the bad pattern:**
  - https://github.com/securego/gosec — G401/G505
  - https://codeql.github.com/codeql-query-help/go/go-weak-crypto-algorithm/
  - https://github.com/OWASP/Go-SCP

---
### 3. `go-security.crypto.math-rand` — math/rand for security tokens

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** math/rand used for session tokens/ids.

**Static detection.** AST: math/rand in auth packages.

**LLM role.** Allow math/rand for simulations.

**False-positive guards.** Non-security sampling.

**Public examples of the bad pattern:**
  - https://github.com/securego/gosec — G404
  - https://github.com/OWASP/Go-SCP
  - https://pkg.go.dev/crypto/rand

---
### 4. `go-security.crypto.hardcoded-key` — Hardcoded cryptographic keys

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | high |

**What it is.** Byte slices used as AES keys from string literals.

**Static detection.** Detect crypto key sizes + literal sources.

**LLM role.** LLM: is it a test vector (AES NIST)?

**False-positive guards.** RFC test vectors in _test.go.

**Public examples of the bad pattern:**
  - https://github.com/securego/gosec — G101-ish secrets
  - https://github.com/OWASP/wrongsecrets
  - https://github.com/gitleaks/gitleaks

---
### 5. `go-security.sql.string-concat` — SQL built via string concat/fmt

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | high |

**What it is.** Query = fmt.Sprintf("...%s", user).

**Static detection.** AST taint-ish: fmt.Sprintf/string + to database/sql Query.

**LLM role.** LLM: confirm user control.

**False-positive guards.** Static table names from const allowlist.

**Public examples of the bad pattern:**
  - https://github.com/securego/gosec — G201/G202
  - https://go.dev/doc/database/sql-inject
  - https://github.com/OWASP/Go-SCP

---
### 6. `go-security.cmd.shell` — exec.Command with shell and user input

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | high |

**What it is.** bash -c / sh -c with concatenated input.

**Static detection.** Detect Command("bash","-c", ...).

**LLM role.** LLM: input sources.

**False-positive guards.** Fixed scripts.

**Public examples of the bad pattern:**
  - https://github.com/securego/gosec — G204
  - https://github.com/OWASP/Go-SCP
  - https://pkg.go.dev/os/exec

---
### 7. `go-security.path.traversal` — filepath join with user input without Clean

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** os.Open(filepath.Join(base, user)).

**Static detection.** Patterns without filepath.Clean / root confinement.

**LLM role.** LLM: is base a trusted sandbox?

**False-positive guards.** Already using os.Root / safejoin.

**Public examples of the bad pattern:**
  - https://github.com/securego/gosec — G304
  - https://go.dev/blog/osroot
  - https://github.com/cyphar/filepath-securejoin

---
### 8. `go-security.auth.jwt-unverified` — JWT accepted without signature/claims validation

| Field | Value |
| --- | --- |
| **Severity** | critical |
| **Target confidence** | medium |

**What it is.** JWT accepted without real validation: `jwt.ParseUnverified` in production paths, keyfuncs that ignore `token.Method`, `jwt.WithoutClaimsValidation`, or explicit `UnsafeAllowNoneSignatureType`. Note: golang-jwt v4+ rejects `alg=none` by default — do not claim otherwise or the finding loses credibility.

**Static detection.** Detect ParseUnverified outside _test.go; keyfunc bodies that never check token.Method; WithoutClaimsValidation / UnsafeAllowNoneSignatureType; imports of abandoned dgrijalva/jwt-go or golang-jwt < v4.

**LLM role.** LLM: library version caveats.

**False-positive guards.** Decode-only debug tools.

**Public examples of the bad pattern:**
  - https://github.com/golang-jwt/jwt
  - https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
  - https://github.com/OWASP/Go-SCP

---
### 9. `go-security.cookie.secure-flags` — Cookies missing Secure/HttpOnly/SameSite

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** http.SetCookie without flags.

**Static detection.** AST on http.Cookie literals.

**LLM role.** Localhost HTTP dev exception medium→low.

**False-positive guards.** Non-browser APIs.

**Public examples of the bad pattern:**
  - https://github.com/OWASP/Go-SCP
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
  - https://github.com/gin-gonic/gin — secure cookie examples

---
### 10. `go-security.csrf.missing` — State-changing handlers without CSRF

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | low |

**What it is.** POST forms without CSRF middleware in web apps.

**Static detection.** Heuristic framework detection + missing middleware.

**LLM role.** LLM: is API token-only JSON?

**False-positive guards.** Pure REST with bearer auth.

**Public examples of the bad pattern:**
  - https://github.com/gorilla/csrf
  - https://github.com/OWASP/Go-SCP
  - https://github.com/gin-gonic/gin

---
### 11. `go-security.ssrf.user-url` — HTTP client fetches user-controlled URL

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** http.Get(req.FormValue(...)).

**Static detection.** Taint from request to client.Do.

**LLM role.** LLM: allowlist hosts?

**False-positive guards.** URL fixed constants.

**Public examples of the bad pattern:**
  - https://github.com/securego/gosec
  - https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
  - https://github.com/swisscom/go-ssrf-filter

---
### 12. `go-security.deserialization.gob` — Untrusted gob/json decode without size limits (DoS)

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** gob/json decode of untrusted network input with no size limit. In Go this is a resource-exhaustion (DoS) risk, not Java-style deserialization RCE — the finding must say so to stay credible.

**Static detection.** Detect gob/json decoders reading directly from net.Conn / request bodies without io.LimitReader / MaxBytesReader.

**LLM role.** Prefer json with typed structs.

**False-positive guards.** Trusted internal RPC.

**Public examples of the bad pattern:**
  - https://pkg.go.dev/encoding/gob
  - https://github.com/OWASP/Go-SCP
  - https://github.com/securego/gosec

---
### 13. `go-security.file.perm-world` — os.WriteFile with 0666/0777

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | high |

**What it is.** World-writable files.

**Static detection.** Detect permission literals.

**LLM role.** Ignore /tmp scratch with short life if proven.

**False-positive guards.** Intentional shared sockets.

**Public examples of the bad pattern:**
  - https://github.com/securego/gosec — G306
  - https://pkg.go.dev/os#WriteFile
  - https://github.com/OWASP/Go-SCP

---
### 14. `go-security.pprof.exposed` — net/http/pprof registered on public server

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** import _ pprof on production listen address.

**Static detection.** Detect pprof import + ListenAndServe :80/:443.

**LLM role.** Allow localhost-only debug servers.

**False-positive guards.** Explicit debug builds.

**Public examples of the bad pattern:**
  - https://pkg.go.dev/net/http/pprof
  - https://github.com/securego/gosec
  - https://github.com/google/pprof

---
### 15. `go-security.grpc.insecure` — grpc.WithInsecure / NewServer without creds

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** Cleartext gRPC.

**Static detection.** Detect WithTransportCredentials(insecure.NewCredentials()) in prod paths.

**LLM role.** Localhost tests OK.

**False-positive guards.** _test.go.

**Public examples of the bad pattern:**
  - https://github.com/grpc/grpc-go
  - https://grpc.io/docs/guides/auth/
  - https://github.com/securego/gosec

---
### 16. `go-security.reflect.unsafe` — unsafe.Pointer casts on network data

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | low |

**What it is.** unsafe casts of buffers from net.Conn.

**Static detection.** LLM-only for now — a static “unsafe near network reads” heuristic is too FP-prone to ship.

**LLM role.** LLM: is cast size-checked?

**False-positive guards.** Performance parsers with proven bounds.

**Public examples of the bad pattern:**
  - https://pkg.go.dev/unsafe
  - https://go.dev/doc/security/best-practices
  - https://github.com/securego/gosec — G103

---
### 17. `go-security.template.missing-escape` — text/template for HTML

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** text/template used where html/template required.

**Static detection.** Detect text/template with HTML-like filenames or http handlers.

**LLM role.** LLM: output content-type.

**False-positive guards.** Email plain text.

**Public examples of the bad pattern:**
  - https://pkg.go.dev/html/template
  - https://github.com/OWASP/Go-SCP
  - https://github.com/securego/gosec — G203

---
### 18. `go-security.dir.listing` — http.FileServer on broad directories

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** FileServer(http.Dir(".")) exposes .git.

**Static detection.** Detect Dir(".") / Dir("/") patterns.

**LLM role.** Recommend embed.FS or narrow roots.

**False-positive guards.** Intentional static sites without secrets.

**Public examples of the bad pattern:**
  - https://pkg.go.dev/net/http#FileServer
  - https://github.com/OWASP/Go-SCP
  - https://github.com/securego/gosec

---
### 19. `go-security.authz.missing` — Authenticated routes without authorization check

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | low |

**What it is.** Middleware sets user but handler never checks role.

**Static detection.** Mostly LLM discovery with auth middleware signals.

**LLM role.** High value, low confidence without framework model.

**False-positive guards.** Public routes.

**Public examples of the bad pattern:**
  - https://github.com/OWASP/Go-SCP
  - https://github.com/casbin/casbin
  - https://github.com/go-chi/chi

---
### 20. `go-security.rate-limit.missing` — Public auth endpoints without rate limit

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | low |

**What it is.** Login/password reset handlers without limiter.

**Static detection.** Heuristic route names + missing middleware.

**LLM role.** LLM discovery.

**False-positive guards.** Internal networks.

**Public examples of the bad pattern:**
  - https://github.com/ulule/limiter
  - https://github.com/OWASP/Go-SCP
  - https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html

---
### 21. `go-security.log.secrets` — Logging passwords/tokens

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | medium |

**What it is.** log.Printf("%+v", req) including password fields.

**Static detection.** Detect log of structs with Password/Token fields.

**LLM role.** LLM: is field redacted?

**False-positive guards.** Error types without sensitive fields.

**Public examples of the bad pattern:**
  - https://github.com/OWASP/Go-SCP
  - https://go.dev/blog/slog
  - https://github.com/securego/gosec

---
### 22. `go-security.session.timeout` — Sessions without expiry

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** Cookie sessions MaxAge=0 permanent.

**Static detection.** Detect session store options.

**LLM role.** LLM framework awareness.

**False-positive guards.** Remember-me intentional with notes.

**Public examples of the bad pattern:**
  - https://github.com/gorilla/sessions
  - https://github.com/alexedwards/scs
  - https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html

---
### 23. `go-security.crypto.static-nonce` — Hardcoded nonce/IV with AES-GCM/CTR

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** A fixed or all-zero nonce passed to AEAD Seal (or a constant IV for CTR/CBC) reuses keystream; with GCM, nonce reuse breaks both confidentiality and authentication.

**Static detection.** AST: byte-slice literal or `make([]byte, 12)` never passed to rand.Read flowing into gcm.Seal / cipher.NewCTR / NewCBCEncrypter IV position.

**LLM role.** Confirm the nonce is not derived per-message (counter/SIV schemes with documented uniqueness are legitimate).

**False-positive guards.** RFC/NIST test vectors in _test.go; documented deterministic-nonce schemes.

**Public examples of the bad pattern:**
  - https://github.com/securego/gosec — G407 hardcoded nonce/IV
  - https://pkg.go.dev/crypto/cipher#NewGCM — nonce uniqueness requirement
  - https://github.com/OWASP/Go-SCP

---
### 24. `go-security.crypto.constant-time` — Secret comparison not constant-time

| Field | Value |
| --- | --- |
| **Severity** | medium |
| **Target confidence** | medium |

**What it is.** Comparing MACs, tokens, or signatures with `==` / `bytes.Equal` admits timing side channels; should be `hmac.Equal` / `subtle.ConstantTimeCompare`.

**Static detection.** Changed `==` / `!=` expressions where one operand is an authentication or signature HTTP header (directly or through one unmodified local alias) and the other is a secret-like identifier.

**LLM role.** Is the comparison attacker-observable (network handler) vs local config check?

**False-positive guards.** Non-secret identifiers; code already inside subtle/hmac helpers; comparisons of hashed values where timing is not exploitable.

**Public examples of the bad pattern:**
  - https://pkg.go.dev/crypto/subtle#ConstantTimeCompare
  - https://pkg.go.dev/crypto/hmac#Equal
  - https://github.com/argoproj/argo-cd/pull/27884#discussion_r3257647841 — human review of a webhook Authorization header compared with `==`
  - https://github.com/OWASP/Go-SCP

---
### 25. `go-security.archive.zip-slip` — Archive extraction without path confinement (Zip Slip)

| Field | Value |
| --- | --- |
| **Severity** | high |
| **Target confidence** | high |

**What it is.** `filepath.Join(dest, entry.Name)` over zip/tar entries lets `../` names escape the destination and overwrite arbitrary files.

**Static detection.** Loops over zip.Reader.File / tar.Next() joining entry names into Create/OpenFile/MkdirAll without a confinement check (filepath.IsLocal, Clean+HasPrefix with separator, securejoin, os.Root).

**LLM role.** Verify the guard actually anchors — HasPrefix without a trailing separator check is bypassable (`/dest-evil`); flag weak guards at medium.

**False-positive guards.** Archives from trusted build pipelines only (downgrade, don't suppress — provenance changes).

**Public examples of the bad pattern:**
  - https://github.com/securego/gosec — G305
  - https://github.com/snyk/zip-slip-vulnerability
  - https://pkg.go.dev/path/filepath#IsLocal

---

## Implementation roadmap (after approval)
1. P0 static rules + fixtures (vulnerable/clean).
2. LLM enhancement on structured signals.
3. Discovery prompts evidence-gated.
4. Precision bake-off on public repos.

**P0 priorities:** InsecureSkipVerify, SQL concat, shell exec, path traversal, zip-slip, static nonce, math/rand tokens, hardcoded keys, pprof exposed.
