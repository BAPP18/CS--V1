# Cybersecurity Toolkit

A lightweight Python cybersecurity toolkit for learning and portfolio use. The project combines several defensive/security-analysis utilities in one interactive CLI:

- multi-threaded TCP port scanner;
- password strength checker and secure password generator;
- SSH/web access-log analyzer;
- CVE lookup using the NVD API;
- phishing URL heuristic analyzer;
- network packet sniffer using Scapy.

> **Authorized use only.** Use the network-oriented modules only on systems, networks, interfaces, and data that you own or are explicitly authorized to test.

## Why this project exists

This repository is designed as a practical cybersecurity portfolio project. It demonstrates Python fundamentals, networking, log analysis, API consumption, input validation, simple detection heuristics, and defensive security tooling.

## Features

| Tool | What it does | Notes |
|---|---|---|
| Port Scanner | Checks a TCP port range using worker threads | Intended for authorized assets only |
| Password Tool | Estimates password strength and generates cryptographically secure passwords | Uses Python `secrets` |
| Log Analyzer | Detects repeated failed SSH logins and high-volume 404 patterns | Heuristic detection |
| CVE Lookup | Searches public NVD CVE records by product/version keyword | Supports optional NVD API key |
| Phishing URL Analyzer | Scores suspicious URL characteristics | Heuristic only; not a verdict engine |
| Packet Sniffer | Displays basic IPv4 TCP/UDP packet metadata | Requires suitable privileges |

## Requirements

- Python 3.10+
- Internet access for NVD lookups
- Administrator/root privileges for packet capture on many systems

Install dependencies:

```bash
git clone https://github.com/BAPP18/CS--V1.git
cd CS--V1
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run

```bash
python main.py
```

Menu:

```text
==================================================
 CYBERSECURITY TOOLKIT
==================================================
 [1] Port Scanner
 [2] Password Strength Checker + Generator
 [3] Log Analyzer
 [4] Vulnerability Scanner (NVD API)
 [5] Phishing URL Detector
 [6] Network Packet Sniffer
 [0] Keluar
==================================================
```

## Optional NVD API key

NVD can apply stricter rate limits to unauthenticated requests. If you have an API key:

```bash
export NVD_API_KEY="your-key"
```

The application reads it from the environment; do not commit API keys to Git.

## Testing

Run:

```bash
python -m unittest discover -s tests -v
```

The included tests focus on deterministic logic such as URL analysis, password generation, and log parsing. Network scanning and packet capture should be tested only in controlled environments.

## Project structure

```text
CS--V1/
├── main.py
├── requirements.txt
├── README.md
├── .gitignore
├── tests/
│   ├── test_log_analyzer.py
│   ├── test_password_tool.py
│   └── test_phishing_detector.py
└── modules/
    ├── __init__.py
    ├── log_analyzer.py
    ├── packet_sniffer.py
    ├── password_tool.py
    ├── phishing_detector.py
    ├── port_scanner.py
    └── vuln_scanner.py
```

## Limitations

- Port scanning is TCP-connect based; it is not a replacement for Nmap.
- Phishing detection is heuristic and can produce false positives/negatives.
- CVE keyword matching does not prove that a host is vulnerable.
- Log thresholds are simple defaults and should be tuned for the environment.
- Packet capture currently focuses on basic IPv4 TCP/UDP metadata.

## Security & ethics

This toolkit is intended for education, defensive analysis, and authorized testing. Do not use it to scan, intercept, or analyze systems or traffic without permission.

## Roadmap

- JSON/CSV output
- configurable detection thresholds
- structured logging
- richer CVE filtering and pagination
- unit/integration test expansion
- optional CLI arguments in addition to the interactive menu
