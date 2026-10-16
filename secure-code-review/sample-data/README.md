# Demonstration accounts and data policy

The vulnerable application's source creates two deliberately weak local-only training accounts in `demo_users.db`. The partially remediated application starts with an empty `users` table.

No user database or request/response log is committed. Use only synthetic accounts; generated SQLite files remain ignored.

A future positive-login regression should explicitly provision a synthetic Argon2 hash, record the database starting state, and test correct and incorrect passwords before claiming successful secure-login behavior. See `../docs/HTTP_REGRESSION_PLAN.md`.
