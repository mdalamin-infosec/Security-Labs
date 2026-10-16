# HTTP security regression plan

Status: **not yet executed and retained**.

Run both applications on loopback only and use disposable synthetic databases.

Minimum cases:

| Area | Vulnerable app | Remediated app |
| --- | --- | --- |
| Health/basic route | Record status/body | Record status/body |
| User disclosure | Observe password/config exposure where implemented | Verify response excludes password data |
| SQL input | Controlled lab SQL metacharacter username | Verify parameter binding prevents query reinterpretation |
| Invalid ping target | Observe current behavior | Expect rejection of non-IP input |
| Controlled shell marker | Harmless local marker input | Verify remediated path does not invoke a shell |
| Valid ping target | Record behavior | Record direct argument execution behavior |
| Positive login | Demo credential path | Seed a synthetic Argon2 hash before claiming success |

Retain HTTP status, sanitized response body, app revision, database starting state and exact commands. Do not expose real credentials.
