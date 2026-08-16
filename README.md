<h1 align="center">DetecTI - Cyber Lead Intelligence</h1>

<div align="center">

<img width="90" src="https://avatars.githubusercontent.com/u/129181562?s=200&v=4" alt="DetecTI Security Logo">

### Modern External Attack Surface Mapping & Threat Intelligence Engine
**Asynchronous • Modular • High-Concurrency • EPSS + CISA KEV Prioritization • Shodan • crt.sh • Reverse WHOIS**

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Pydantic v2](https://img.shields.io/badge/Pydantic-v2-green.svg)](https://docs.pydantic.dev/)

</div>

---

## 🚀 Overview

**DetecTI-CLI** is a high-performance Python 3.11+ CLI tool designed for **External Attack Surface Management (EASM)**, **Reconnaissance**, and **Vulnerability Intelligence**.

It maps exposed internet infrastructure (domains, subdomains, IPs, and open ports), correlates organizations via **Reverse WHOIS**, and enriches identified CVEs with real-world exploitation risk data (**EPSS + CISA KEV**), weakness classification (**CWE Name**), and Proof of Concepts (**ExploitDB + GitHub PoCs**).

---

## ⚡ Key Features

- **🌐 Infrastructure & Asset Mapping**:
  - Direct IP, CIDR subnets (`192.168.1.0/24`), Domain, and Shodan search query support.
  - Port, service, product, version, and banner discovery.
  - Automatic web service identification (`http://` vs `https://`).
- **🔍 Subdomain & Domain Correlation**:
  - **Certificate Transparency (crt.sh)** for comprehensive subdomain enumeration.
  - **Reverse WHOIS**: Correlates domains by registrant email, organization name, or domain (WhoisFreaks API + HackerTarget free fallback).
  - Shodan DNS historical record mapping.
- **🛡️ Advanced Threat Intelligence & Risk Prioritization**:
  - **NVD 2.0 API**: CVSS v3.1, v3.0, and v2.0 base scores, severity levels, and **CWE Name** weakness mapping.
  - **FIRST EPSS**: Exploit Prediction Scoring System (probability percentage & percentile).
  - **CISA KEV**: Catalogs vulnerabilities actively exploited in real-world attacks & ransomware campaigns.
  - **ExploitDB & GitHub PoCs**: Direct links to public exploits and proof-of-concept repositories.
- **📊 Executive & Structured Reporting**:
  - Rich, interactive terminal tables with colored risk badges.
  - Structured **JSON** export (`--format json`).
  - Executive **Markdown** report generation (`--format markdown`).

---

## 📦 Installation

### Prerequisites
- Python 3.11 or higher

### Install with pip or editable mode
```bash
git clone https://github.com/detectibr/DetecTI-CLI.git
cd DetecTI-CLI

# Install in editable mode
pip install -e .

# Or install dependencies via requirements.txt
pip install -r requirements.txt

chmod +x detecti-cli

#Install and update Exploit Database
./detecti-cli update-xdb
```

---

## ⚙️ Configuration & API Keys

DetecTI-CLI works out-of-the-box with free fallbacks (crt.sh, HackerTarget, EPSS, CISA KEV, GitHub PoC API), but you can configure API keys for full power:

Create a `.env` file or export environment variables:
```bash
# Required for Shodan queries
export SHODAN_API_KEY="your_shodan_api_key_here"

# Optional: Censys Platform API v3 PAT Token and Org ID
export CENSYS_PAT_TOKEN="your_censys_pat_token_here"
export CENSYS_ORG_ID="your_censys_org_id_here" # (Optional for multi-tenant orgs)

# Optional: Accelerates NVD API rate limits
export NVD_API_KEY="your_nvd_api_key_here"

# Optional: For structured WhoisFreaks reverse WHOIS lookups
export WHOISFREAKS_API_KEY="your_whoisfreaks_api_key_here"

# Optional: GitHub token for PoC queries
export GITHUB_TOKEN="your_github_token_here"
```

You can verify your configuration anytime:
```bash
./detecti-cli config-check
```

---

## 💻 Usage & CLI Examples

### 1. Scan a Single IP or CIDR Subnet
```bash
# Scan single IP
./detecti-cli scan -t 142.250.191.68

# Scan CIDR range
./detecti-cli scan -t 142.250.191.0/24
```

### 2. Scan a Domain (Subdomains + Reverse WHOIS + Infrastructure)
```bash
./detecti-cli scan -t spacex.com
```

### 3. Scan a Specific CVE with EPSS, CISA KEV, and PoCs
```bash
detecti-cli scan -t CVE-2021-44228
```

### 4. Advanced Shodan Search Queries
You can pass custom Shodan search queries directly into the target `-t` parameter. **Always enclose the query in double quotes ("")**.

```bash
# Search by Organization Name
./detecti-cli scan -t "org:'ACME LTDA'" -m all -f acme.md

# Search by City and Open Service
./detecti-cli scan -t "city:'washington' port:8080" -o markdown -f washington.md

# Search by SSL Certificate Organization
./detecti-cli scan -t "ssl.cert.subject.org:'SpaceX'"
```
> 💡 **Tip**: Explore all available search filters in the official [Shodan Search Filters Guide](https://www.shodan.io/search/filters).

### 5. Select Specific Modules
```bash
./detecti-cli scan -t example.com -m crtsh,reverse_whois
```

### 6. Filter Vulnerabilities by CVSS Severity
```bash
./detecti-cli scan -t 142.250.191.68 --cvss critical
```

### 7. Export Reports (JSON & Markdown)
```bash
# Export Markdown executive report
./detecti-cli scan -t example.com -o markdown -f report.md

# Export JSON data
./detecti-cli scan -t example.com -o json -f report.json

# Export all formats to a directory
./detecti-cli scan -t example.com -o all -d ./reports
```

### 8. Update ExploitDB Database
```bash
./detecti-cli update-xdb
```

---

## 🏗️ Architecture

```
DetecTI-CLI/
├── detecti-cli            # Typer & Rich Command Line Interface
├── config.py              # Pydantic Settings & Environment Loading
├── core/                  
│   ├── engine.py          # Asynchronous Pipeline & Correlation Engine
│   └── models.py          # Unified Pydantic v2 Finding & Intel Schemas
├── modules/               # Plug-and-Play Intelligence Collectors
│   ├── base.py            # BaseModule Abstract Interface
│   ├── crtsh.py           # Certificate Transparency (Subdomains)
│   ├── reverse_whois.py   # Reverse WHOIS (Hybrid WhoisFreaks + Free Fallback)
│   ├── shodan.py          # Shodan Host, DNS, Range & Query Scanner
│   ├── censys.py          # Censys Platform API v3 Asset & Host Intelligence (CenQL)
│   ├── nvd.py             # NVD 2.0 + EPSS Probability + CISA KEV
│   └── exploitdb.py       # ExploitDB & GitHub PoC Collector
├── reporters/             # Export Engines
│   ├── json_reporter.py   # Formatted JSON Exporter
│   └── markdown_reporter.py # Executive Markdown Exporter
├── utils/                 
│   ├── http.py            # Centralized Async HTTPX Client (Retries & Rate Limits)
│   └── logger.py          # Rich Console Theme, Tables & Formatters
├── tests/                 # Comprehensive Unit & Integration Tests
└── pyproject.toml         # Modern Packaging Definition
```

---

## 🧪 Testing

Run test suite with `pytest`:
```bash
pytest -v
```

---

## 🛠️ Creator and Maintainer

<a href="https://github.com/Ls4ss">
  <img src="https://avatars.githubusercontent.com/u/25537761?v=4" width="100px;" style="border-radius: 50%;" alt="Ls4ss Profile"/>
  <br />
  <sub><b>Lucas S. (Ls4ss)</b></sub>
</a>

Feel free to open Issues or submit Pull Requests to contribute!
