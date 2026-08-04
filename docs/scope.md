# go/security — mission and scope

Source of truth for what this adversary is *for*.

- **Package:** `go-security`
- **Factory routing:** human PR comments are attributed to this adversary only when they match **In scope**.
- **Languages / surfaces:** Go

## Mission

Review Go trust boundaries: authn/authz, crypto, transport security, and secret handling in application code.

## In scope (fair miss if humans raised it and we did not)

- Authn/authz gaps and broken access control in Go code
- Weak crypto, insecure random, bad TLS settings
- Secret handling mistakes in Go (not raw secret scanning alone)
- Trust-boundary violations and SSRF-prone URL handling in app code

## Out of scope (not a miss for this adversary)

- Generic eng judgment without security angle
- Pure concurrency races without security impact
- Committed credential blobs (secrets adversary)
- CI secrets wiring (github-actions)
- Non-Go

## Factory grading rule

- **In scope + human raised it + this adversary did not surface it** → real miss → suggested issue for **this** package
- **Out of scope** → do not grade as a miss for this adversary
- **Better fit for another adversary** → route there; do not double-count as a miss here
- **Unclear** → prefer out-of-scope for grading
