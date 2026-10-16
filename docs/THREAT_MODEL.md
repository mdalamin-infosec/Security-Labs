# Repository threat model

## Assets

- Detection rules and their integrity.
- Lab configurations and scope boundaries.
- Vulnerability-assessment reports and cached CVE data.
- Local runtime evidence that may contain IP addresses, service banners or credentials.
- Secure-code-review demo databases and application secrets.

## Trust boundaries

```text
GitHub / committed source
        |
        v
Local lab host ---- isolated VirtualBox host-only network
        |                         |
        v                         v
CI / offline fixtures       Kali / Ubuntu / Metasploitable2
        |
        v
External public data (NVD) only where explicitly requested
```

## Primary risks and controls

| Risk | Control |
| --- | --- |
| Scanning an unintended network | Explicit CIDR allowlists and literal target configuration in NetSentry |
| Publishing sensitive runtime artifacts | Root `.gitignore` excludes outputs, PCAPs, SQLite databases, local environments and secrets |
| Treating detections as compromise | Documentation distinguishes a rule match from confirmed malicious activity |
| Treating CVE matches as exploitability | Reports call them candidates and require analyst applicability review |
| Unsafe automated response | IDS response remains optional/manual; production containment is outside scope |
| Secrets in source | `.env.example` files contain placeholders; runtime `.env` files stay ignored |
| Supply-chain drift | Locked Rust dependencies and pinned GitHub Actions revisions; Python dependencies are explicit project requirements |
| Lab-to-production overclaim | Results identify synthetic, real-engine and controlled-live evidence classes separately |

## Out of scope

- Production SOC coverage guarantees.
- Enterprise asset discovery at scale.
- Credentialed vulnerability assessment.
- Automated exploitation.
- Autonomous blocking or endpoint isolation.
- Multi-user authenticated production dashboards.
