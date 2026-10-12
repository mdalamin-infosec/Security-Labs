# Security Labs — Reproducible Cybersecurity Projects

Hands-on, educational cybersecurity labs covering **network intrusion detection** and **secure coding review**. This repository includes code, Suricata rules, shell scripts, screenshots, and technical reports. The instructions below explain how someone using a **new PC or laptop** can prepare the environment, clone the repository, run each lab, and verify expected behavior.

> **Intended environment:** Debian/Ubuntu-family Linux (including Kali for traffic generation). Windows users should use Linux virtual machines for the network lab. These are **demonstration projects**, not turnkey production security controls.

## 1. Projects

| Lab | Purpose | What you need | Setup guide |
| --- | --- | --- | --- |
| [Network Intrusion Detection System](NetworkIntrusionDetectionSystem/README.md) | Detect lab ICMP, SYN bursts, SSH attempts, and TCP port 4444 using Suricata | VirtualBox, Ubuntu Server VM, Kali VM, Suricata, Bash | [Full installation, configuration, testing](NetworkIntrusionDetectionSystem/README.md#setup-from-a-fresh-pc-or-laptop) |
| [Secure Coding Review](SecureCodingReview/README.md) | Compare intentionally vulnerable and partially remediated Rust REST APIs | Linux, Rust/Cargo, C compiler, curl, ping | [Full installation, build, execution, testing](SecureCodingReview/README.md#setup-from-a-fresh-pc-or-laptop) |

## 2. PC/laptop requirements

These are **planning estimates**, not tested minimum hardware specifications.

| Requirement | For Rust review only | For two-VM Suricata lab |
| --- | --- | --- |
| Operating system | Debian/Ubuntu Linux recommended | Linux/Windows/macOS host able to run VirtualBox; Linux guests |
| RAM | ~4 GB or more practical | ~8 GB host minimum workable, **16 GB recommended** |
| Storage | Several GB free for dependencies/build outputs | About **40–60 GB** free for two VM disks and snapshots |
| Internet | Needed for first-time package/crate downloads | Needed for OS installation/packages; lab traffic remains isolated |
| Privileges | `sudo` to install OS packages | Admin access on host; `sudo` in Ubuntu/Kali guests |

### Software installation checklist

- **Both labs:** Git and a terminal; Internet access for initial downloads.
- **Suricata lab:** [VirtualBox](https://www.virtualbox.org/wiki/Downloads), [Ubuntu Server ISO](https://ubuntu.com/download/server), [Kali Linux VM/ISO](https://www.kali.org/get-kali/), Suricata, optional UFW.
- **Rust lab:** [Rust toolchain and Cargo](https://www.rust-lang.org/tools/install), build tools, `curl`, `iputils-ping`, SQLite command-line client (optional).

> The network IDS cannot automatically inspect all traffic between arbitrary VMs. In this lab the **Ubuntu Server itself is the test target**: traffic sent to its monitored network interface is what Suricata can observe.

## 3. Get this repository on your computer

Install Git on Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y git
```

Clone the existing repository:

```bash
git clone https://github.com/mdalamin-infosec/Security-Labs.git
cd Security-Labs
ls
```

Expected top-level directories:

```text
Security-Labs/
├── README.md
├── .gitignore
├── NetworkIntrusionDetectionSystem/
│   ├── README.md
│   ├── rules/local.rules
│   ├── scripts/monitor_alerts.sh
│   ├── scripts/response.sh
│   ├── reports/detection_report.md
│   └── screenshots/
└── SecureCodingReview/
    ├── README.md
    ├── vulnerable_app/{Cargo.toml,src/main.rs}
    ├── secure_app/{Cargo.toml,src/main.rs}
    └── security_report.md
```

**Important:** To operate Suricata **inside Ubuntu Server**, clone/download this repository **inside that VM as well**, or copy the `NetworkIntrusionDetectionSystem` directory into it. Cloning on your host PC does not automatically place the scripts inside a VM.

## 4. Choose your setup path

### Path A: Suricata network IDS (2 virtual machines)

1. Install VirtualBox on your host and prepare **Ubuntu Server** and **Kali Linux** VMs.
2. Configure each VM with **Adapter 1 = NAT** (package downloads) and **Adapter 2 = the same Host-only network** (isolated traffic).
3. In Ubuntu, install Suricata; find your interface with `ip -br -4 addr`.
4. In Ubuntu, clone the repository, install `rules/local.rules`, configure `HOME_NET`, `rule-files`, and the `af-packet` interface in `/etc/suricata/suricata.yaml`.
5. Validate with `sudo suricata -T -c /etc/suricata/suricata.yaml`, restart its service, then send authorized test packets from Kali to the Ubuntu IP.
6. Monitor alerts in `/var/log/suricata/fast.log`. Optional manual firewall response is **not necessary** to demonstrate detection.

**Use the detailed commands and troubleshooting notes in the [Suricata README](NetworkIntrusionDetectionSystem/README.md#setup-from-a-fresh-pc-or-laptop).**

### Path B: Rust secure code review (1 Linux machine/VM)

1. Install the Linux prerequisites, Rust (via rustup), Cargo, and Clippy.
2. Clone the repository.
3. Build/check the two Rust applications with `cargo check --locked --manifest-path ...`.
4. Start the vulnerable version **on localhost port 8080**, and the remediated version **on localhost port 8081**.
5. Use `curl` to check the documented endpoints. Inspect code and the security report to compare risks and remediations.

**Use the detailed commands and troubleshooting notes in the [Rust README](SecureCodingReview/README.md#setup-from-a-fresh-pc-or-laptop).**

## 5. What you should see

| Lab | Expected initial verification | If it fails |
| --- | --- | --- |
| Suricata | `suricata -T` passes, service is running, lab ICMP triggers SID `1000001` in `fast.log` when packets reach the capture interface | Check VM network, actual interface/IP, YAML config, rules, and log output |
| Vulnerable Rust app | `curl http://127.0.0.1:8080/` returns a demonstration home page | Check compilation errors, port availability, and localhost binding |
| Remediated Rust app | `curl http://127.0.0.1:8081/health` returns `{"status":"healthy"}` | Check build, environment, and port availability |

**Known behavior:** The remediated Rust application creates an **empty user table** and has **no user-registration or seeding workflow**. A new installation therefore cannot demonstrate a successful login without extra, separately implemented user provisioning. See [limitations](SecureCodingReview/README.md#important-remaining-security-gaps).

## 6. Security and maintenance notes

- Work only on systems and networks you own or are authorized to test.
- Run the vulnerable Rust application on **127.0.0.1 only**, in an isolated training environment. Never publish its test credentials or expose its port publicly.
- Suricata alerts represent **rule matches**, not proof of compromise. Avoid auto-blocking IPs on a production machine.
- The `secure_app` fixes selected patterns but **is not production-ready**: GET credentials, missing authorization, and broad ping targets remain concerns.
- Do **not** commit Cargo `target/` directories, generated `.db` files, local logs, `.env` secrets, or real private data. The root `.gitignore` covers common generated files.
- Some original rule/script messages include the string `CODEALPHA`; that is a **legacy alert label** used by the scripts' filters, not a requirement to create any repository by that name.

## 7. Reports and evidence

- [Detection report](NetworkIntrusionDetectionSystem/reports/detection_report.md)
- [Secure coding review report](SecureCodingReview/security_report.md)
- [Network IDS screenshots](NetworkIntrusionDetectionSystem/screenshots/)

## 8. Authoritative references

- [Suricata quickstart and configuration](https://docs.suricata.io/en/latest/quickstart.html)
- [VirtualBox host-only networking](https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/networkingdetails.html)
- [Rust installation (official)](https://www.rust-lang.org/tools/install)
- [Cargo book](https://doc.rust-lang.org/cargo/)
