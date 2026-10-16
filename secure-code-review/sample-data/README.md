# Demonstration accounts

The vulnerable application's [source](../src/vulnerable-app/src/main.rs)
creates two deliberately weak local-only training accounts in `demo_users.db`.
The partially remediated application starts with an empty `users` table.

No user database or request/response log is committed here. Use only synthetic
accounts; generated SQLite files are ignored. TODO: provide and test explicit
Argon2-hash provisioning before claiming a successful secure login.
