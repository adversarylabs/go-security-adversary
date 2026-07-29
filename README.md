# go/security

Go Security reviews trust boundaries, cryptography, TLS, authentication, authorization, and secret handling.

Catalog id: **`go/security`** (domain/name taxonomy).

```sh
adversary pull go/security
adversary run go/security --path . --base main --head feature
```

The review covers disabled TLS verification, unconstrained JWT algorithms, and credentials written to logs. Severity reflects realistic boundary impact.

## Fixtures and calibration

Five graded fixtures pair vulnerable paths with secure counterexamples. The 61-repository corpus calibrates trust-boundary and secure-default judgment.

## Automatic detection

`adversary auto` selects Go Security for changed Go source. Future runtime semantic detection can conservatively narrow this to security-relevant changes.

## Development

Run `npm test`, `adversary validate .`, and `adversary pack --check .`.
