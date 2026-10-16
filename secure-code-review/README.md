# Secure Coding Review — Rust Web API

A hands-on secure-code-review lab with two Rust **Actix-web + SQLite** REST APIs: `vulnerable_app`, containing intentionally unsafe code, and `secure_app`, which demonstrates selected remediations. The steps below explain **exactly what to install and how to run it from a new laptop/PC**.

> **Safety:** `vulnerable_app` is deliberately insecure and must **never** be exposed to public networks. Both programs bind to `127.0.0.1` in the supplied source. Use only in an authorized local training environment.

## Project objectives

- Install a Rust development toolchain and build these apps from source.
- Observe common SQL injection, command injection, password storage, secret, and data-exposure flaws in source code.
- Compare the insecure patterns with parameterized SQL, Argon2 password-hash verification, validation, and shell-free process calls.
- Run simple endpoint checks and document **remaining security limitations**.

## What software you need

| Dependency | Required? | Purpose |
| --- | --- | --- |
| **Debian/Ubuntu Linux** | Recommended environment | Build and run this documented setup; Linux `ping` arguments used in source |
| Git | Yes | Clone source repository |
| Rust toolchain (`rustc`, `cargo`) | Yes | Compile and run Rust code |
| Clippy (`cargo clippy`) | Recommended | Static lint checks (not a security certification) |
| `build-essential` | Yes on typical Linux builds | C compiler/linker for Rust native dependencies (bundled SQLite) |
| `curl` | Yes for the test commands | Call local HTTP endpoints |
| `iputils-ping` | Yes for the `/ping` demonstrations | System `ping` executable launched by both applications |
| `sqlite3` CLI | Optional | Examine local SQLite tables |
| `pkg-config`, `libssl-dev` | Recommended development tools | Common native library build prerequisites; not necessarily used by every locked crate |

**Compatibility:** These commands target Debian 13 / current Ubuntu desktop or server releases. Windows users can run a Debian/Ubuntu VM or WSL2. The network IDS project is better suited to **actual VMs**, not WSL2 packet capture.

## Project layout

```text
secure-code-review/
├── README.md
├── vulnerable_app/
│   ├── Cargo.toml
│   ├── Cargo.lock
│   └── src/main.rs
├── secure_app/
│   ├── Cargo.toml
│   ├── Cargo.lock
│   └── src/main.rs
└── security_report.md
```

**Generated on first run:** `vulnerable_app/demo_users.db`, `secure_app/secure_users.db`, and `target/` build directories. Do not commit them.

## Setup from a fresh PC or laptop

### Step 1 — Install Linux packages

**On Debian/Ubuntu Linux (not inside a Windows command prompt):**

```bash
sudo apt update
sudo apt install -y git curl build-essential pkg-config libssl-dev \
  iputils-ping sqlite3
```

### Step 2 — Install stable Rust + Cargo + Clippy

**Recommended official rustup installation:**

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Follow the on-screen install prompt. This command executes an installer downloaded from the official Rust project; review its contents first if required by your organization's security policy. **Do not run the Rust installer with `sudo`.**

Load Rust into this terminal and install/check tools:

```bash
. "$HOME/.cargo/env"
rustup default stable
rustup component add clippy rustfmt
rustc --version
cargo --version
cargo clippy --version
```

`rustup` installs the toolchain in your user account. If Rust is already installed and working, do **not** run the installer again; check `rustc --version` and `cargo --version` first. The `Cargo.lock` files determine specific crate versions; a current stable toolchain is recommended. Internet access is required for first-time crate downloads.

### Step 3 — Clone the repository

```bash
git clone https://github.com/mdalamin-infosec/Security-Labs.git
cd Security-Labs/secure-code-review
ls vulnerable_app/Cargo.toml secure_app/Cargo.toml
```

If the repository is already on your PC, skip `git clone` and `cd` into **`Security-Labs/secure-code-review/`**. All following relative commands assume you are in this folder unless they explicitly use `cd`.

### Step 4 — Compile both apps and run lint checks

```bash
cargo check --locked --manifest-path vulnerable_app/Cargo.toml
cargo check --locked --manifest-path secure_app/Cargo.toml
cargo clippy --locked --manifest-path vulnerable_app/Cargo.toml
cargo clippy --locked --manifest-path secure_app/Cargo.toml
```

`cargo check` detects compile errors without building a final binary. `cargo clippy` provides lint guidance but cannot prove that a program is secure. If `--locked` reports that a lockfile needs updating, **investigate and explicitly update dependencies** rather than silently changing a reproducible dependency set. Avoid committing generated `target/` files.

### Step 5 — Run the deliberately vulnerable version

**Terminal A** (in the `SecureCodingReview` folder):

```bash
cd vulnerable_app
cargo run --locked
```

Expected: app listens on `http://127.0.0.1:8080` and creates **`demo_users.db` in the working directory**. The code seeds two **insecure demo accounts**; their credentials are intentionally weak and should never be reused.

**Terminal B** (same Linux system):

```bash
curl -i http://127.0.0.1:8080/
curl -i 'http://127.0.0.1:8080/user?id=1'
```

For review, note that `/user` discloses a stored password in this deliberately vulnerable demonstration. **Do not use real personal data.** To stop the running server, press `Ctrl+C` in Terminal A.

### Step 6 — Run the partially remediated version

**Terminal A** (start from the `SecureCodingReview` directory, or navigate to it):

```bash
cd secure_app
export APP_SECRET='local-demo-only-replace-me'
cargo run --locked
```

Expected: app listens on `http://127.0.0.1:8081` and creates an **empty** `secure_users.db` SQLite database in its working directory.

**Terminal B:**

```bash
curl -i http://127.0.0.1:8081/health
curl -i 'http://127.0.0.1:8081/ping?host=127.0.0.1'
curl -i 'http://127.0.0.1:8081/user?id=1'
```

Expected:

- `GET /health`: HTTP 200, `{"status":"healthy"}`.
- `GET /ping?host=127.0.0.1`: HTTP 200 with `ping` result if system `ping` is installed and can execute.
- `GET /user?id=1`: **HTTP 404 on a fresh DB**, because no users are seeded.
- `GET /login?...`: **HTTP 401 on a fresh DB** for the same reason. No sign-up route or provisioning script is included, so a successful login is **not** reproducible from the current repository without adding valid Argon2-hashed user provisioning.

**Important:** The secure demo loads an optional `APP_SECRET`, but still falls back to a development placeholder and does not show a complete production secret-management implementation.

### Step 7 — Optional database inspection

Use a *new terminal* and run these commands from the `SecureCodingReview` folder:

```bash
sqlite3 vulnerable_app/demo_users.db '.tables'
sqlite3 secure_app/secure_users.db '.tables'
```

Do this **after** running each program once. On a fresh clone, those `.db` files do not exist; `sqlite3` may otherwise create an unintended empty file.

### Step 8 — Compare code and findings

```bash
diff -u vulnerable_app/src/main.rs secure_app/src/main.rs | less
cat security_report.md
```

Exit `less` with `q`. Compare user-controlled HTTP input into SQL statements, subprocess calls, and responses. This is a code-review exercise; it is not an audited authentication service.

## Endpoint reference

| Endpoint | Vulnerable app (`8080`) | Remediated app (`8081`) |
| --- | --- | --- |
| `/` | Demo landing page | Demo landing page |
| `/login?username=...&password=...` | Vulnerable SQL construction, plaintext password comparison | Parameterized SQL and Argon2 verification; **no default users** |
| `/user?id=1` | Exposes password | Returns username/ID only **if a user exists**, but lacks authorization |
| `/ping?host=127.0.0.1` | Builds a shell command from input | Parses IP and invokes `ping` directly (but still permits arbitrary IP destinations) |
| `/debug-info` | Exposes an embedded demo secret | Route removed |
| `/health` | Not provided | JSON health check |

**Never send real passwords through these GET request URLs.** Query-string credentials can be recorded in logs/history. They exist here to show risky design patterns, including one that persists in the supposedly secure example.

## Troubleshooting

| Symptom | Fix/check |
| --- | --- |
| `cargo: command not found` | Run `. "$HOME/.cargo/env"`, reopen shell, confirm Rust installation |
| `linker 'cc' not found` | Install `build-essential` |
| Cargo cannot download crates | Check Internet, certificate/proxy configuration, crates.io access |
| `Address already in use` | `ss -ltnp | grep -E ':8080|:8081'`; stop the other process or use a separate lab VM |
| `/ping` fails | `command -v ping`; ensure `iputils-ping` installed |
| Secure `/login` returns 401 | Expected on a fresh database: no seeded user and no registration endpoint |
| `secure_users.db` seems missing | App creates it relative to **current working directory**; start from `secure_app/` |
| `cargo clippy` has findings | Record the warnings; lint suggestions do not replace security assessment |

## Security findings

| Finding | Insecure implementation | Remediation demonstrated |
| --- | --- | --- |
| SQL injection | SQL string interpolation | Parameterized `rusqlite::params!` |
| Credential storage | Plaintext stored in SQLite | Argon2 hash **verification** (hash provisioning absent) |
| Shell injection | `sh -c` with user input | Parse IP, invoke `ping` without a shell |
| Embedded secret | Hardcoded source constant, debug route | Read env var and remove debug route |
| Sensitive data leak | Returns password from `/user` | Omits password from response |
| Weak validation | String ID and limited constraints | Integer ID and basic validation |

See [Security Review Report](security_report.md) for narrative findings and recommendations.

## Important remaining security gaps

Despite its name, `secure_app` is **not production-ready**:

- Login still uses **GET query parameters** instead of an HTTPS-protected POST body.
- The `/user` endpoint has **no authentication or authorization**.
- No user enrollment, seeded Argon2 password hashes, session management, or rate limiting is provided.
- `APP_SECRET` permits an insecure placeholder fallback and is not applied to a demonstrated authentication mechanism.
- `/ping` accepts arbitrary valid IP addresses; this is still an outbound-network/SSRF-style risk without an allowlist and rate limiting.
- Database failures are handled more carefully, but there is no comprehensive automated security-test suite.
- Secure defaults would additionally require TLS, least privilege, secrets management, logging without sensitive data, and dependency security review.

## Reproducibility and cleanup

- First build may take time and disk space because Cargo downloads and compiles crates.
- The supplied `Cargo.lock` files should be kept; `target/` and generated SQLite databases should **not** be committed.
- To remove temporary build outputs, run from `secure-code-review/`:

```bash
cargo clean --manifest-path vulnerable_app/Cargo.toml
cargo clean --manifest-path secure_app/Cargo.toml
```

- Stop running servers with `Ctrl+C` in their terminal. The generated `.db` files contain **only local demo data** if you have not added your own records; back up anything needed before deleting them.

**Official references:** [Rust installation](https://www.rust-lang.org/tools/install) · [Cargo book](https://doc.rust-lang.org/cargo/) · [Rust book](https://doc.rust-lang.org/book/)
