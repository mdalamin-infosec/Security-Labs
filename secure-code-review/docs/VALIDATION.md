# Rust validation record

## Completed build/lint checks

The owner-run unified validation recorded:

```text
cargo check --locked vulnerable-app: PASS
cargo check --locked secure-app: PASS
cargo clippy --locked vulnerable-app: PASS
cargo clippy --locked secure-app: PASS
```

These results establish that both committed application variants build/check successfully under the recorded toolchain and pass the invoked Clippy checks. They do **not** prove endpoint security.

## Runtime regression status

Actual HTTP response evidence is still pending. The expected cases are documented in [HTTP_REGRESSION_PLAN.md](HTTP_REGRESSION_PLAN.md).

A successful 401 against an empty secure database would not prove correct Argon2 login behavior. A future positive-login test should seed a synthetic Argon2 hash explicitly and test both correct and incorrect passwords.

## Claim boundary

The project currently supports build/lint and source-review claims. It does not claim complete remediation or production readiness.
