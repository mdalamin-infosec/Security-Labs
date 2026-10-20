# Rust Application Security Review

A CodeAlpha secure-coding exercise comparing a deliberately vulnerable Actix-web/
SQLite application with a partially remediated version. It demonstrates how
application-level security mistakes can remain in memory-safe code.

## Findings and changes present in the source

| Issue | Vulnerable implementation | Remediated implementation |
| --- | --- | --- |
| SQL injection | Interpolate request values into SQL | Bind Rusqlite parameters |
| Command injection | Include input in `sh -c` | Parse an IP address and invoke `ping` directly |
| Password handling | Store and compare plaintext passwords | Verify an existing Argon2 hash |
| User-data disclosure | Return stored passwords from `/user` | Select only ID and username |
| Debug disclosure | Expose configuration through `/debug-info` | Remove the endpoint |

[Vulnerable source](src/vulnerable-app/src/main.rs) · [Remediated source](src/secure-app/src/main.rs) · [Review report](docs/security-review.md)

## Build and run

Install Rust/Cargo and a C build toolchain for bundled SQLite. From this directory:

```bash
cargo check --locked --manifest-path src/vulnerable-app/Cargo.toml
cargo check --locked --manifest-path src/secure-app/Cargo.toml
cargo clippy --locked --manifest-path src/vulnerable-app/Cargo.toml
cargo clippy --locked --manifest-path src/secure-app/Cargo.toml
cargo run --locked --manifest-path src/vulnerable-app/Cargo.toml
```

The vulnerable app listens on **127.0.0.1:8080**. Stop it with Ctrl+C; start the
remediated variant using:

```bash
cargo run --locked --manifest-path src/secure-app/Cargo.toml
```

That variant listens on **127.0.0.1:8081**. Use disposable databases and synthetic
credentials. Initial dependency resolution requires network access.

## Remaining application work

The remediated app creates a table but does not seed a valid Argon2 user. A successful
login response also does not create a session. Credentials still travel in GET query
parameters; `/user` and `/ping` lack authorization; parsed ping targets are unrestricted.
The environment secret is unused and has a development fallback.

The supplied validation notes record earlier Cargo/Clippy passes. Rust was unavailable
in the documentation review environment, so no fresh build or HTTP pass is asserted.
The next milestone is a temporary-database HTTP run covering valid/invalid login,
SQL handling, response disclosure and ping input, followed by authorization fixes.

[Existing validation record](docs/VALIDATION.md) · [HTTP regression plan](docs/HTTP_REGRESSION_PLAN.md)
