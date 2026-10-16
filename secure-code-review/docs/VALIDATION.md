# Rust validation plan — runtime checks pending

The cleanup preserved both application sources. It did not have a Rust
toolchain and did not execute either application. Everything below is
**TODO: test**. Record Rust/Cargo versions, locked dependency revisions, actual
stdout/stderr, HTTP status/body and database starting state.

Run `cargo check --locked` and `cargo clippy --locked` for both manifests as
shown in the README. A Clippy result does not prove security. Start each app
from its own directory, using a fresh synthetic database.

## Exact localhost endpoint cases
With the two applications running:
```bash
curl -i http://127.0.0.1:8080/
curl -i 'http://127.0.0.1:8080/user?id=1'
curl -i http://127.0.0.1:8080/debug-info
curl -i http://127.0.0.1:8081/health
curl -i 'http://127.0.0.1:8081/user?id=1'
curl -i 'http://127.0.0.1:8081/ping?host=not-an-ip'
curl -i 'http://127.0.0.1:8081/ping?host=127.0.0.1'
```

Expected from source, not observed yet: the vulnerable user/debug responses
disclose demo data; secure health is 200; secure user 1 is 404 on an empty DB;
invalid IP is 400. A valid ping depends on the installed executable/permissions.

Controlled SQL-input comparison, using demo accounts only:
```bash
curl -i -G http://127.0.0.1:8080/login --data-urlencode "username=admin' -- " --data-urlencode 'password=wrong'
curl -i -G http://127.0.0.1:8081/login --data-urlencode "username=admin' -- " --data-urlencode 'password=wrong'
```

The first query is intended to expose string-interpolated SQL; the second
should not interpret the username as SQL. A 401 on the empty secure DB does
not prove valid-user password verification. TODO: add explicit synthetic
Argon2-hash provisioning, then test correct and incorrect passwords.

Controlled shell-input comparison (local educational app only):
```bash
curl -i -G http://127.0.0.1:8080/ping --data-urlencode 'host=127.0.0.1; printf LAB_MARKER'
curl -i -G http://127.0.0.1:8081/ping --data-urlencode 'host=127.0.0.1; printf LAB_MARKER'
```

Record whether the vulnerable response includes the harmless marker and the
remediated app rejects the non-IP input. This is a planned test, not an
executed exploit result. No Atomic Red Team test IDs are claimed.

TODO: personally demonstrate and explain the remaining GET-credential,
authorization, enrollment, secret-fallback and outbound-target limitations.
