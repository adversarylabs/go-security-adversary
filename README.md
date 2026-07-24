# Go Security adversary

Go Security reviews trust boundaries, cryptography, TLS, authentication, authorization, and secret handling.

The initial review covers disabled TLS verification, unconstrained JWT algorithms, and credentials written to logs. Severity reflects realistic boundary impact.

## Fixtures and calibration

Five graded fixtures pair vulnerable paths with secure counterexamples. The 61-repository corpus calibrates trust-boundary and secure-default judgment.

## Automatic detection

`adversary auto` selects Go Security for changed Go source. Future runtime semantic detection can conservatively narrow this to security-relevant changes.

## Development

Run `npm test`, `adversary validate .`, and `adversary pack --check .`.
