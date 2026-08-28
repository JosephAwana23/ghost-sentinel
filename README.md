# 🛡️ Ghost-Sentinel: Dual-AI Telemetry & SOC Auditor

**Ghost-Sentinel** is a containerized, mobile-responsive Security Operations Center (SOC) dashboard and automated audit suite. It bridges offensive adversary modeling and automated defensive engineering using a dual-AI architecture powered by **Gemini** and **OpenAI**.

---

## ⚡ Core Architecture

Ghost-Sentinel evaluates system telemetry and network scans through two synchronized AI personas:

* 🔴 **GHOST (Red Team)**: Models exploit pathways, attack surfaces, and maps findings directly to **MITRE ATT&CK** techniques.
* 🔵 **AEGIS (Blue Team)**: Assesses detection blind spots, calculates threat risk scores (0–100), outputs copy-pasteable bash hardening scripts, and generates production-ready **Sigma rules** for SIEM deployment.
* 🤖 **CyberBuddy War Room**: An integrated RAG (Retrieval-Augmented Generation) query drawer that inspects local SQLite audit logs to answer tactical questions in natural language.

---

## 🛠️ Security & Recon Modules

* **Port & Service Enumeration**: Fast socket checks (`ss -tuln`), fast TCP discovery (`nmap -F`), and deep service version detection (`nmap -sV`).
* **OSINT & Network Recon**: Target subnet discovery (`nmap -sn`), DNS diagnostics (`dig`), WHOIS registry lookup, and hop analysis (`traceroute`).
* **Web & SSL Auditing**: Web server security scans (`nikto`) and SSL/TLS certificate inspection via `openssl`.
* **File Integrity Monitoring (FIM)**: Recursive SHA-256 cryptographic hash walk across system scripts (`.py`, `.sh`, `.conf`) to detect unauthorized modifications.
* **Persistent Audit Logging**: SQLite database logging timestamps, modules, target endpoints, risk scores, and AI evaluations.

---

## 🚀 Quickstart Guide

### 1. Prerequisites
* [Docker](https://www.docker.com/) & [Docker Compose](https://docs.docker.com/compose/)
* API Keys for **Google Gemini** and **OpenAI**

### 2. Clone the Repository
```bash
git clone [https://github.com/JosephAwana23/ghost-sentinel.git](https://github.com/JosephAwana23/ghost-sentinel.git)
cd ghost-sentinel