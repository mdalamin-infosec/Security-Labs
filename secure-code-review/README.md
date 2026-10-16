# Secure code review: Rust web APIs

## Objective

Compare a deliberately vulnerable Actix-web/SQLite application with a partially remediated counterpart and demonstrate that memory-safe Rust does not remove application-layer security risks.

## Current validated evidence

| Check | Result |
| --- | --- |
| `cargo check --locked` vulnerable app | PASS |
| `cargo check --locked` secure app | PASS |
| Clippy vulnerable app | PASS |
| Clippy secure app | PASS |
| Static source comparison | Retained |
| Runtime HTTP regression | Not yet retained |
| Successful secure-user login | Not claimed |

## Reviewed changes

- SQL interpolation → parameterized queries
- shell command construction → parsed IP + direct process arguments
- password field removed from user response
- Argon2 verification path added
- sensitive debug endpoint removed from the remediated variant

These changes improve specific weaknesses but do not make the sample a production authentication service.

## Run build/lint checks

```bash
cargo check --locked --manifest-path src/vulnerable-app/Cargo.toml
cargo check --locked --manifest-path src/secure-app/Cargo.toml
cargo clippy --locked --manifest-path src/vulnerable-app/Cargo.toml
cargo clippy --locked --manifest-path src/secure-app/Cargo.toml
```

## Remaining runtime proof

The next milestone is an actual localhost HTTP regression run covering health, SQL-input handling, disclosure, invalid IP and controlled shell-input cases. See [HTTP_REGRESSION_PLAN.md](docs/HTTP_REGRESSION_PLAN.md).

## Limitations

The remediated demo still has intentional gaps: GET credentials, missing authorization/session/enrollment controls, a placeholder/fallback secret path, arbitrary valid IP ping targets, and startup failure paths. It is a learning artifact, not a deployable login service.

See [security review](docs/security-review.md), [validation](docs/VALIDATION.md), and the root [roadmap](../docs/ROADMAP.md).
