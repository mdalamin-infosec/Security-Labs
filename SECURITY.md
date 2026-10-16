# Security policy

This repository contains intentionally vulnerable training code, detection rules, and active-scanning examples for isolated authorized labs.

## Safe use

- Run scanning, attack simulation, and response tests only on systems you own or are explicitly authorized to test.
- Keep lab traffic on isolated/private networks.
- Review scripts and target configuration before execution.
- Do not commit real credentials, private keys, packet captures, databases, or unsanitized runtime logs.

## Reporting a repository vulnerability

If you identify a security issue in the repository itself, avoid publishing exploit details in a public issue. Prefer GitHub's private security-reporting / Security Advisory mechanism when available, or contact the repository owner privately.

## Scope note

The intentionally vulnerable Rust sample and Metasploitable2 lab target are educational artifacts. Their known weaknesses are not considered vulnerabilities in this repository unless the issue is an unintended repository/automation problem.
