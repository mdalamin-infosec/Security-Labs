# Rust Secure Coding Review

A secure coding review project developed for the CodeAlpha
Cyber Security Internship.

## Task 3 — Secure Coding Review

This project audits an intentionally vulnerable Rust web application
and demonstrates how the identified vulnerabilities can be remediated.

## Technology Stack

- Rust
- Actix-web
- SQLite
- Rusqlite
- Cargo
- Cargo Clippy
- Manual code review

## Project Structure

```text
SecureCodingReview/
├── vulnerable_app/
│   ├── Cargo.toml
│   └── src/
│       └── main.rs
├── secure_app/
│   ├── Cargo.toml
│   └── src/
│       └── main.rs
├── security_report.md
├── README.md
└── screenshots/
