# Secure Coding Review Report

## Project

CodeAlpha Cyber Security Internship

Task 3 — Secure Coding Review

## Programming Language

Rust

## Application

Small Actix-web REST application using SQLite.

Two versions are included:

- `vulnerable_app`
- `secure_app`

The vulnerable application was created only for authorized
secure-code-review training.

---

# Review Methodology

The review used:

1. Manual source-code inspection
2. Cargo compiler checks
3. Cargo Clippy static analysis when available
4. Comparison of vulnerable and remediated implementations

---

# Findings

## Finding 1 — Hardcoded Secret

**Severity:** Medium

### Vulnerable Code

The vulnerable application stores a secret directly in source code.

### Risk

Secrets committed to source repositories may become visible to
developers, CI systems, Git history, or public repositories.

### Recommendation

Load secrets from environment variables or a dedicated secrets
management system.

### Remediation

The secure implementation reads `APP_SECRET` from the environment.

---

## Finding 2 — SQL Injection

**Severity:** High

### Vulnerable Code

User-controlled data is concatenated directly into SQL statements.

### Risk

An attacker may alter the intended SQL query and access or manipulate
data.

### Recommendation

Use parameterized SQL queries.

### Remediation

The secure version uses Rusqlite parameters:

`params![value]`

instead of string concatenation.

---

## Finding 3 — Plain-Text Password Storage

**Severity:** High

### Vulnerable Code

Passwords are stored directly in the SQLite database.

### Risk

If the database is exposed, user passwords are immediately readable.

### Recommendation

Store password hashes using a password hashing algorithm designed
for credential storage.

### Remediation

The secure implementation is designed to verify Argon2 password
hashes instead of comparing plain-text passwords.

---

## Finding 4 — Sensitive Information Exposure

**Severity:** High

### Vulnerable Code

The `/user` endpoint returns stored passwords.

The `/debug-info` endpoint exposes application configuration.

### Risk

Sensitive information may be disclosed to unauthorized users.

### Recommendation

Return only the minimum information required by the client.

### Remediation

The secure `/user` endpoint returns only:

- User ID
- Username

Sensitive configuration endpoints were removed.

---

## Finding 5 — Command Injection Risk

**Severity:** Critical

### Vulnerable Code

User-controlled input is included inside a shell command.

### Risk

Shell interpretation of untrusted input may allow unintended command
execution.

### Recommendation

Avoid invoking a shell with user-controlled input.

Validate inputs and pass arguments directly to the required program.

### Remediation

The secure implementation:

1. Parses the input as an IP address.
2. Rejects invalid values.
3. Executes `ping` directly.
4. Does not invoke `sh -c`.

---

## Finding 6 — Weak Input Validation

**Severity:** Medium

### Vulnerable Code

Several request parameters are accepted without validation.

### Risk

Unexpected or malicious values may reach security-sensitive
operations.

### Recommendation

Apply strict allow-list validation and appropriate type checking.

### Remediation

The secure version:

- Uses integer types for user IDs.
- Rejects invalid IDs.
- Applies length limits.
- Parses ping targets as IP addresses.

---

## Finding 7 — Unsafe Error Handling

**Severity:** Medium

### Vulnerable Code

The vulnerable application frequently uses `unwrap()`.

### Risk

Unexpected failures may cause application crashes.

### Recommendation

Handle errors explicitly and return controlled error responses.

### Remediation

The secure version uses explicit error matching for database and
process operations.

---

# Secure Coding Best Practices

- Never concatenate untrusted input into SQL.
- Avoid shell execution when direct process APIs are available.
- Validate input using strict allow-lists.
- Store passwords using modern password hashing algorithms.
- Never expose password hashes or secrets in API responses.
- Keep credentials outside source code.
- Use least-privilege database and operating-system permissions.
- Avoid verbose production error messages.
- Review dependencies regularly.
- Run static analysis and dependency auditing tools.
- Keep Rust dependencies updated.
- Perform peer review for security-sensitive code.

---

# Conclusion

The secure coding review identified multiple application-level
security problems even though Rust provides strong memory-safety
guarantees.

Rust reduces many memory-corruption risks, but developers must still
protect applications against:

- SQL injection
- Command injection
- Authentication weaknesses
- Sensitive-data exposure
- Configuration mistakes
- Weak input validation

The `secure_app` demonstrates safer alternatives for the identified
issues.
