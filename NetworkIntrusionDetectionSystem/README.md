# Network Intrusion Detection System

A network-based intrusion detection project developed as part of the **CodeAlpha Cyber Security Internship — Task 4**.

This project uses **Suricata** to monitor network traffic, detect suspicious activity, generate alerts, and demonstrate a simple defensive response workflow.

## Project Objective

The goal of this project is to:

- Configure a network-based intrusion detection system
- Monitor network traffic continuously
- Create custom Suricata detection rules
- Detect suspicious or potentially malicious activity
- Generate alerts
- Implement a basic defensive response mechanism
- Document the detection results

## Lab Environment

The project was tested in a VirtualBox lab environment.

```text
Kali Linux
IP: 192.168.56.103

        |
        |  VirtualBox Lab Network
        |  192.168.56.0/24
        |

Ubuntu Server
IP: 192.168.56.102
Interface: enp0s8
Role: Suricata IDS
