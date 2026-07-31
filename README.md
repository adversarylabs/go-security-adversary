# go/security

**go/security** reviews Go source for high-confidence **trust-boundary** defects: disabled TLS verification, SQL and shell injection, weak crypto, path/archive escapes, credential leakage, and exposed debug endpoints.

It is a **domain security reviewer**, not a general Go linter. It prefers silence over noisy style advice. When it reports, it should be something a staff security engineer would open a ticket for.

## What it does

1. **Discovers** non-test Go files (`*.go`, excluding `*_test.go`).
2. **Runs deterministic detectors** (regex / structure over source) that emit stable rule ids with file:line evidence.
3. **Synthesizes a review** (severity, impact, recommendation) from those signals.
4. Optionally **enhances** with a model when the CLI provides one (`permissions.model: true`) — explanation and ranking only, not freestyle vulnerability invention.

It never executes the scanned project, never installs dependencies into it, and never needs network access to the target.

## What it detects

Every **shipped rule id**, severity, and short description lives in **[CHECKS.md](CHECKS.md)** — the audit surface for “what does this adversary look for?”

Broader priority / roadmap notes (P0 / P1 / LLM-only) are in [docs/issue-catalog.md](docs/issue-catalog.md).

Highlights:

| Area | Examples |
| --- | --- |
| Transport | `InsecureSkipVerify: true` |
| Injection | SQL string concat / `fmt.Sprintf` into Query/Exec; `sh -c` / `bash -c` |
| Paths | Unconfined `filepath.Join` + open; zip/tar slip on extract |
| Crypto | `math/rand` for tokens; hardcoded AES keys; static GCM nonces |
| Secrets | Credentials in logs, argv, URLs, world-readable credential files |
| Debug | `net/http/pprof` on a public server |
| Auth | JWT parse without algorithm allowlist |

### Ownership boundaries

Other official adversaries own adjacent classes so findings stay non-duplicative:

| Concern | Owned by |
| --- | --- |
| HTTP server/client timeouts, CORS, open redirects, WebSocket origin | [`go/http`](https://github.com/adversarylabs/go-http-adversary) |
| DB transaction/row lifecycle, GORM raw SQL (ORM-specific) | [`go/database`](https://github.com/adversarylabs/go-database-adversary) |
| High-precision committed secrets (AWS keys, PATs, etc.) | [`security/secrets`](https://github.com/adversarylabs/secrets-adversary) |

## Precision stance

- **High confidence** only for deterministic, evidence-backed patterns.
- Clean fixtures must stay quiet; vulnerable fixtures must fire (see `fixtures/p0-*` and graded tiers).
- Prefer missing a weak signal over a false positive on normal Go code (e.g. path traversal only when a join is **opened** without confinement).
