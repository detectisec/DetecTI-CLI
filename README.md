<h1 align="center">DetecTI - Cyber Lead Intelligence</h1>

<div align="center">

<img width="90" src="https://avatars.githubusercontent.com/u/129181562?s=200&v=4" alt="DetecTI Security Logo">

### Modern External Attack Surface Mapping & Threat Intelligence Engine
**Asynchronous • Modular • High-Concurrency • EPSS + CISA KEV Prioritization • Masscan & Nuclei Active Scanning • Shodan • Censys • crt.sh • Reverse WHOIS**

[![Website: detecti.com.br](https://img.shields.io/badge/Official_Website-detecti.com.br-00d4ff.svg)](https://detecti.com.br)
[![Documentation: Official Docs](https://img.shields.io/badge/Documentation-Official_Docs-8A2BE2.svg)](https://detecti.com.br/docs/detecti-cli/en.html)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code Style: Pydantic v2](https://img.shields.io/badge/Pydantic-v2-green.svg)](https://docs.pydantic.dev/)

</div>

---

## 📚 Official Documentation & Introduction

> 📖 Complete guides, installation, CLI usage, architecture, and threat intelligence scoring are available in the [**DetecTI-CLI Official Documentation**](https://detecti.com.br/docs/detecti-cli/en.html).

### 🛡️ About DetecTI - Cyber Lead Intelligence
**DetecTI-CLI** (officially **DetecTI - Cyber Lead Intelligence**) is an enterprise-grade cyber intelligence and External Attack Surface Management (EASM) platform engineered by [DetecTI Security](https://detecti.com.br). It serves as the primary execution engine of the proprietary **R.A.D.A.R. Framework** (*Reconnaissance, Analysis, Diagnosis, Assessment, and Resolution*), materializing the organization's institutional pillars: *Open Source Collaboration*, *Technical Excellence*, *Ethical Hacking*, and *Pragmatism*.

In cybersecurity operations, a **Cyber Lead** is an exposed asset or attack vector discovered, enriched with threat intelligence, actively validated, and qualified by its real-world exploitation risk. DetecTI-CLI transforms noisy internet telemetry into qualified, prioritized intelligence so security teams can focus on what matters most.

---

## 🚀 Overview

**DetecTI - Cyber Lead Intelligence** is a high-performance Python 3.11+ engine designed for **External Attack Surface Management (EASM)**, **Active & Passive Asset Reconnaissance**, and **Vulnerability Weaponization Intelligence**.

It maps exposed internet infrastructure (domains, subdomains, IPs, open services, and banners), correlates organizational relationships via **Reverse WHOIS** and **Certificate Transparency**, executes high-speed active verification with **Masscan**, performs targeted vulnerability validation with **Nuclei** strictly against verified active endpoints (*Verified Active Rule*), and enriches identified CVEs with real-world exploitation risk data (**FIRST EPSS + CISA KEV**), weakness taxonomy (**CWE Name**), provenance tracking (**Vulnerability Source**), and public weaponization proofs (**ExploitDB + GitHub PoCs**).

---

## 🔄 Engine Data Flow & Correlation Pipeline

The DetecTI engine executes an asynchronous, multi-stage pipeline designed to discover, correlate, and prioritize internet-facing attack surfaces with threat intelligence feeds.

```mermaid
flowchart TD
    classDef input fill:#1e293b,stroke:#00d4ff,stroke-width:2px,color:#fff
    classDef recon fill:#1e1e2e,stroke:#3b82f6,stroke-width:2px,color:#fff
    classDef enrich fill:#2a1b3d,stroke:#9333ea,stroke-width:2px,color:#fff
    classDef active fill:#3b1e5a,stroke:#a855f7,stroke-width:2px,color:#fff
    classDef intel fill:#3b1e1e,stroke:#ef4444,stroke-width:2px,color:#fff
    classDef correlate fill:#143024,stroke:#10b981,stroke-width:2px,color:#fff
    classDef output fill:#2d2d2d,stroke:#f59e0b,stroke-width:2px,color:#fff

    TARGET([🎯 Target Input: IP / CIDR / Domain / CVE / Query]):::input --> CLASSIFY[Target Classification & Validation]:::input

    subgraph Stage1 [Stage 1: Primary Reconnaissance & Target Discovery]
        CLASSIFY -->|Domain / Email| CRTSH[📜 crt.sh: Certificate Transparency Subdomains]:::recon
        CLASSIFY -->|Domain / IP / Email| WHOIS[🏢 Reverse WHOIS: Associated Root Domains]:::recon
        CLASSIFY -->|Domain / IP / CIDR / Query| SHODAN[🛰️ Shodan: Host Profile, Subnet Scans, DNS & Banners]:::recon
        CLASSIFY -->|Direct IP / Fallback| CENSYS_DIRECT[🌐 Censys: Direct IP Profile]:::recon
    end

    subgraph Stage1_5 [Stage 1.5: Complementary Censys Host Enrichment]
        CRTSH & WHOIS & SHODAN -->|All Discovered Host IPs| IP_EXTRACT[Extract Unique Discovered IPs]:::recon
        IP_EXTRACT -->|Parallel Host Dossiers| CENSYS_ENRICH[🌐 Censys: Deep Port, Service & TLS Scan per IP]:::recon
    end

    subgraph Stage1_8 [Stage 1.8: Active Verification & Target Scanning]
        IP_EXTRACT -->|Marked Scan Targets| MASSCAN[⚡ Masscan: High-Speed Port & Banner Grabbing]:::active
        MASSCAN -->|Verified Active Ports| NUCLEI[🛡️ Nuclei: Active Vulnerability Scan]:::active
    end

    subgraph Stage2 [Stage 2: Threat Intelligence & Vulnerability Scoring]
        SHODAN & CENSYS_DIRECT & CENSYS_ENRICH & NUCLEI -->|Aggregated CVE IDs & Findings| CVE_AGG[CVE Aggregator & Deduplication]:::enrich
        CVE_AGG --> NVD[🛡️ NVD 2.0: CVSS Base Score, Severity & CWE Name]:::intel
        CVE_AGG --> EPSS[📈 FIRST EPSS: Real-world Exploit Probability %]:::intel
        CVE_AGG --> CISA[🚨 CISA KEV: Active Exploitation & Ransomware Flag]:::intel
    end

    subgraph Stage3 [Stage 3: Weaponization & PoC Hunting]
        CVE_AGG --> XDB[💣 ExploitDB: Verified Exploits & Shellcodes]:::intel
        CVE_AGG --> GITHUB[🐙 GitHub PoC Hunter: Public Exploit Repositories]:::intel
    end

    subgraph Stage4 [Stage 4: Unified Graph Modeling & Correlation]
        NVD & EPSS & CISA & XDB & GITHUB & NUCLEI --> CORRELATION[🔗 Unified Engine Correlation & Graph Synthesis]:::correlate
        CRTSH & WHOIS & SHODAN & CENSYS_ENRICH & MASSCAN --> CORRELATION
    end

    subgraph Stage5 [Stage 5: Multi-Channel Output]
        CORRELATION --> DB[(💾 SQLite Persistence with Auto-Migrations)]:::output
        CORRELATION --> CLI[📊 Rich Terminal Tables & Risk Badges]:::output
        CORRELATION --> REPORT[📄 JSON, Markdown & HTML Reports]:::output
        CORRELATION --> WEB[🌐 Responsive Cytoscape.js Web Dashboard]:::output
    end
```

### 🔍 Step-by-Step Data Flow:

1. **Target Classification**:
   - Categorizes input into `IP`, `CIDR range`, `Domain`, `CVE-ID`, `Email`, `Custom Query`, or `Batch File`.

2. **Stage 1: Primary Reconnaissance & Target Discovery**:
   - **Shodan**: Primary discovery engine for custom queries (e.g., `org:`, `port:`), CIDR subnets (`192.168.1.0/24`), direct IP lookups, and domain DNS record mapping (resolving subdomains to active `A` record IPs).
   - **Certificate Transparency (crt.sh)**: Discovers issued TLS/SSL certificates to uncover wildcards and hidden subdomains.
   - **Reverse WHOIS (WhoisFreaks API + HackerTarget fallback)**: Identifies associated parent/child domains registered by the same organization.
   - **Censys (Direct IP Lookups)**: Queries host profiles for direct single IP targets, or acts as a primary fallback if Shodan is unconfigured.

3. **Stage 1.5: Complementary Censys Host & Service Enrichment**:
   - Extracts **all unique discovered IPs** and queries parallel host dossiers (`/v3/global/asset/host/{ip}`) to enrich open ports, web service protocols, software versions, banners, TLS certificates, and additional CVEs.

4. **Stage 1.8: Target Management & Active Scanning (Masscan + Nuclei)**:
   - **Masscan Active Port Scan**: Targets marked on the graph are scanned at high speeds with banner grabbing (`--banners`) to verify live exposed services.
   - **Verified Active Rule for Nuclei**: Nuclei vulnerability scanning only executes on **"Verified Active"** endpoints (discovered or validated by Masscan). If an IP target has not yet been scanned with Masscan, a pre-scan verification is executed automatically before dispatching Nuclei templates.

5. **Stage 2: Threat Intelligence & Vulnerability Prioritization**:
   - All unique CVE IDs identified across passive feeds and active Nuclei scans are aggregated and tracked by their provenance (**Vulnerability Source**: `Nuclei`, `NVD`, etc.).
   - **NVD 2.0 API**: Retrieves official CVSS v3.1, v3.0, and v2.0 base scores, vector metrics, and **CWE (Common Weakness Enumeration)** weakness name.
   - **FIRST EPSS API**: Appends real-world exploitation probability percentages (0.0% to 100%) and percentile scores.
   - **CISA KEV Catalog**: Cross-checks vulnerabilities actively leveraged in ransomware and targeted cyber campaigns.

6. **Stage 3: Weaponization & PoC Hunting**:
   - **ExploitDB (searchsploit)**: Matches CVEs against local exploit scripts, PoCs, and shellcodes with verification tags.
   - **GitHub PoC Intelligence**: Queries real-world public exploit repositories and verification status.

7. **Stage 4: Graph Modeling & Relational Synthesis**:
   - Binds assets into a structured, query-rooted hierarchical topology:
     $$\text{Target Query Root} \xrightarrow{\text{MATCHES\_DOMAIN}} \text{Domains / Org Networks} \xrightarrow{\text{HAS\_SUBDOMAIN / CONTAINS\_IP}} \text{Subdomains / IPs} \xrightarrow{\text{RESOLVES\_TO}} \text{Hosts} \xrightarrow{\text{EXPOSES}} \text{Services} \xrightarrow{\text{HAS\_VULN}} \text{CVEs}$$

8. **Stage 5: Persistence & Presentation**:
   - Stores all relationships in a relational SQLite database with auto-migration support.
   - Outputs formatted JSON, Executive Markdown, standalone HTML reports, and interactive web visualization graphs with direct references to [DetecTI Security](https://detecti.com.br).

---

## ⚡ Key Features

- **🌐 Infrastructure & Asset Mapping**:
  - Direct IP, CIDR subnets (`192.168.1.0/24`), Domain, and custom search query support.
  - Port, service, product, version, and banner discovery.
  - Automatic web service URL construction (`http://` vs `https://`).
- **🔍 Subdomain & Domain Correlation**:
  - **Certificate Transparency (crt.sh)** for comprehensive subdomain enumeration.
  - **Reverse WHOIS**: Correlates domains by registrant email, organization name, or domain (WhoisFreaks API + HackerTarget fallback).
  - Shodan DNS historical record mapping.
- **🛡️ Advanced Threat Intelligence & Risk Prioritization**:
  - **NVD 2.0 API**: CVSS base scores, severity levels, and **CWE Name** weakness mapping.
  - **FIRST EPSS**: Exploit Prediction Scoring System (probability percentage & percentile).
  - **CISA KEV**: Catalogs vulnerabilities actively exploited in real-world attacks & ransomware campaigns.
  - **ExploitDB & GitHub PoCs**: Direct links to public exploits and proof-of-concept repositories.
  - **Source Provenance Tracking**: Clear visibility of where each vulnerability was identified (`Nuclei`, `NVD`, etc.) in all graph views, node inspectors, and Risk Metrics accordions.
- **💻 Interactive & Fully Responsive Web Dashboard**:
  - Asynchronous FastAPI web server rendering rich EASM network graphs with Cytoscape.js.
  - **Intuitive Mouse Navigation & Node Organization**:
    - **Left-Click (Drag)**: Pan and navigate smoothly across the canvas.
    - **Left-Click (Node)**: Select single node and inspect deep asset metadata in the Asset Inspector.
    - **Ctrl + Left-Click (Node)** / **Cmd + Left-Click**: Additive sequential multi-selection of target nodes.
    - **Right-Click (Node)**: Custom Context Menu to Collapse/Uncollapse Services or Vulnerabilities, Set/Remove Targets, Focus Node, or Copy Domain/IP/CVE identifiers.
    - **Right-Click (Drag)**: Box area selection to group and reposition multiple nodes together.
    - **Smooth Scroll Wheel**: Seamless zoom in/out centered directly at the cursor position.
  - **Retractable Filters & Controls Drawer**: Smoothly collapse the left sidebar to liberate 100% of the screen for graph exploration across all desktop and mobile devices.
  - **Granular Graph Filters**:
    - `CISA KEV (Known Exploited)`
    - `High EPSS (>50% Exploit Probability)`
    - `Critical Vulnerabilities (CVSS 9.0+)`
    - `Hide Low & Info Findings`
    - `Nuclei Scan Findings Only`
    - `Verified Public PoCs / Exploits`
    - `Exposed Services Branches`
    - `Verified Active Services Only`
    - `Vulnerable Services Only`
  - **Visual Topology & Semantic Relationships**: Interactive graph engine with distinct node geometry, high-contrast colors (Electric Purple root query anchor, Royal Blue ASN octagons, deep blue domains, turquoise subdomains, purple IPs, orange/green service hexagons, red CVE diamonds, and crimson CISA KEV highlights), and directed relationship edges.
  - **Dynamic Database Switcher**: Seamlessly switch between any saved SQLite databases without server restart (including a rich pre-packaged demo dataset in `example.com.sqlite`).
  - **Export Data Menu**: One-click download of active scan data in **JSON**, **Executive Markdown**, and **Standalone HTML** formats.
  - **Floating Action Controls**: Instant access to `📐 Fit to Screen`, `🔍 Reset Zoom`, `🔄 Re-layout`, and **Layout Selector** (`🌳 Hierarchical (Top-Down, Default)`, `🌐 Force-Directed`, `🎯 Concentric`, `▦ Grid`).
  - **Smart Collapsible Clusters (High Fan-Out Optimization)**: Group high-density services or vulnerabilities into clean, collapsible cluster nodes with a dashed border.
  - **Asset Inspector & Risk Metrics Accordions**: Deep-dive into technical properties, CWE descriptions, affected ports, associated domains, weaponized exploit URLs, and explicit vulnerability **Source** attribution.
- **🎯 Target Management & High-Speed Active Port Scanning (Masscan)**:
  - **Right-Click Target Marking & Bulk Selection**:
    - Mark/unmark any individual `IP Address` node as a scan target directly from the Cytoscape graph context menu (**Set as Target** / **Remove Target**).
    - **Bulk Target Addition on Root Nodes**: Right-click on any `Organization`, `Network / ASN`, `Target Root`, or `Domain` node to instantly mark or unmark **all associated descendant IPs** as scan targets in a single click (**Set all N IPs as Targets** / **Remove all N IPs from Targets**).
  - **Inspector Direct Actions**: Toggle individual or bulk target states directly from the **Asset Inspector** drawer for both IP nodes and parent Organization/Domain roots.
  - **Target Management Drawer**: Right-side sliding panel providing real-time target status (`Idle`, `Scanning`, `Completed`, `Failed`), discovered open port counts, port chips with banner tooltips, individual or bulk scan execution, and a live console output stream.
  - **Live Scan Indicator**: Pulsing **`Scanning...`** badge and visual status indicators on the Targets header button while port or vulnerability scans are executing in the background.
  - **Flexible Scan Presets & Rate Control**: Quick port profiles (*Top 100*, *Web Ports*, *All Ports 0-65535*, *Custom*), packet rate slider (100 to 10,000 pps), `-Pn` (disable ping), and `--banners` (banner grabbing & service detection).
  - **Visual Topology Differentiation**:
    - Marked IP nodes display a discreet **Crosshair badge overlay** in the upper-right corner.
    - Services awaiting active verification render in dark slate with dashed amber borders (`#f59e0b`).
    - Confirmed active services render in solid **Emerald Green (#27ae60)** with an emerald border and glow.
    - Active scan service connections render as solid **Emerald Green relationship edges** (`#2ecc71`).
- **🛡️ Active Vulnerability Scanning (Nuclei)**:
  - Integration with ProjectDiscovery's **Nuclei** engine for template-based vulnerability assessment.
  - **Mandatory "Verified Active" Enforcement**: Scans are strictly targeted at ports confirmed open and active via Masscan. Unverified targets trigger an automated pre-scan verification prior to template execution.
  - Configurable severity filters (Critical, High, Medium, Low, Info), protocol/template tags, rate limits, concurrency, and custom flags.
  - Automated database merging, deduplication, and immediate Cytoscape graph node generation with weaponized PoC linkage.
- **🔐 Pre-Flight API Verification & Sanity Checking**:
  - Built-in sanity layer (`config-check` and engine pre-flight) that filters dummy placeholder keys and verifies valid authentication before running scans, preventing silent 401/403 authorization errors.
- **📊 Executive & Structured Reporting**:
  - Automated local SQLite database persistence for mapped targets inside `./data/dbs/`.
  - Rich, interactive terminal tables with colored risk badges.
  - Structured **JSON** export (`--format json`).
  - Executive **Markdown** report generation (`--format markdown`) with official DetecTI Security attribution.
  - Standalone, styled **HTML** report generation (`--format html`) with print-to-PDF formatting.

---

## 📦 Installation

### Prerequisites
- **Python**: 3.11 or higher
- **Masscan** (Required for WebUI Active Port Scanning):
  - Masscan must be installed on your operating system and configured with appropriate Linux capabilities so the WebUI background workers can transmit raw network packets without requiring the web server to run as root.
  ```bash
  # Debian / Ubuntu / Kali Linux
  sudo apt install -y masscan

  # Arch Linux / Manjaro
  sudo pacman -S masscan

  # Fedora / RHEL
  sudo dnf install -y masscan

  # Grant non-root raw socket capabilities to allow WebUI execution:
  sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which masscan)
  ```
- **Nuclei** (Optional / Recommended for Active Vulnerability Scanning):
  - Nuclei should be installed and accessible in your system `PATH` to run active vulnerability scans from the WebUI.
  ```bash
  # Via Go:
  go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

  # Via Binary / Homebrew / Package Manager (Debian/Ubuntu/Kali):
  sudo apt install -y nuclei   # If available in your distribution repo
  # Or download pre-built binary from https://github.com/projectdiscovery/nuclei/releases
  ```

### Install with pip or editable mode
```bash
git clone https://github.com/detectibr/DetecTI-CLI.git
cd DetecTI-CLI

# Install in editable mode
pip install -e .

# Or install dependencies via requirements.txt
pip install -r requirements.txt

chmod +x detecti-cli

# Install and update Exploit Database
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
./detecti-cli scan -t CVE-2021-44228
```

### 4. Advanced Shodan Search Queries
You can pass custom Shodan search queries directly into the target `-t` parameter. **Always enclose the query in double quotes ("")**.

```bash
# Search by Organization Name
./detecti-cli scan -t "org:'ACME LTDA'" -f acme.md

# Search by City and Open Service
./detecti-cli scan -t "city:'washington' port:8080" -o markdown -f washington.md

# Search by SSL Certificate Organization
./detecti-cli scan -t "ssl.cert.subject.cn:'SpaceX'"
```
> 💡 **Tip**: Explore all available search filters in the official [Shodan Search Filters Guide](https://www.shodan.io/search/filters).

### 5. Filter Vulnerabilities by CVSS Severity
```bash
./detecti-cli scan -t 142.250.191.68 --cvss critical
```

### 6. Automatic SQLite Database Persistence & DetecTI Hound Launch
Target scans automatically save all correlated entities (Domains, IPs, Ports, Services, CVEs, PoCs) into `./data/dbs/{target_root}.sqlite` and automatically launch the **DetecTI Hound** WebGUI:

```bash
# Scan a domain (automatically creates ./data/dbs/spacex.com.sqlite and starts Hound)
./detecti-cli scan -t spacex.com

# Scan with custom database name
./detecti-cli scan -t 142.250.191.0/24 --create-db google_net
```
> 💡 All scan databases are centralized in `./data/dbs/` so both the CLI and DetecTI Hound can automatically discover, list, and switch between them. (Note: Standalone CVE lookups like `CVE-2021-44228` do not create databases).

### 7. Export Reports (JSON, Markdown & HTML)
```bash
# Export Markdown executive report
./detecti-cli scan -t example.com -o markdown -f report.md

# Export standalone styled HTML report
./detecti-cli scan -t example.com -o html -f report.html

# Export JSON structured data
./detecti-cli scan -t example.com -o json -f report.json

# Export all formats to a directory
./detecti-cli scan -t example.com -o all -d ./reports
```

### 8. Update ExploitDB Database
```bash
./detecti-cli update-xdb
```

### 9. Interactive EASM Web Dashboard (DetecTI Hound)
Explore the mapped attack surface visually via the interactive web application from previously saved SQLite databases:

```bash
# Start the DetecTI Hound web dashboard (databases are selected dynamically directly in the Web UI)
./detecti-cli hound start

# List available databases from previous scans (stored in ./data/dbs)
./detecti-cli hound list-dbs

# Check the background server status
./detecti-cli hound status

# Stop the web server
./detecti-cli hound stop
```

#### 🌟 Web Dashboard & Cytoscape Graph Highlights:
- **Dynamic Database Switcher**: Switch between any saved SQLite database in `./data/dbs/` directly from the header dropdown without restarting the server.
- **Strict 2-State Service Semantics**:
  - `⚠️ Awaiting Active Confirmation`: Dark slate hexagon with dashed amber border for passive recon findings.
  - `✅ Confirmed Active`: Canonical **Emerald Green** solid hexagon (`#27ae60`) once validated by Masscan active scan.
- **Export Data Menu**: Instant one-click download of the active scan in **JSON**, **Markdown**, or standalone **HTML** format (with built-in print/PDF styling).
- **Interactive Graph Visualization**: Full Cytoscape.js topology with multiple layout algorithms (`⚡ Force-Directed Adv`, `🌳 Hierarchical`, `🎯 Concentric`, `▦ Grid`).
- **Target Management & Active Scans**: In-app Masscan port scanner and Nuclei vulnerability runner with live stream logs.
- **Official Documentation**: Direct integration to the official [DetecTI-CLI Documentation](https://detecti.com.br/docs/detecti-cli/en.html) from the header and sidebar.


---

## 🏗️ Architecture

```
DetecTI-CLI/
├── detecti-cli              # Typer & Rich Command Line Interface entrypoint
├── config.py                # Pydantic Settings, .env & Environment Loader
├── data/                    # Central Scan Data Directory
│   └── dbs/                 # Persistent SQLite Attack Surface Databases (.sqlite)
│       └── example.com.sqlite # Default pre-populated enterprise graph & test dataset
├── core/                    
│   ├── engine.py            # Asynchronous Multi-Stage Pipeline & Correlation Engine
│   ├── models.py            # Unified Pydantic v2 Finding, Host & Intel Data Models
│   └── database/            
│       ├── schema.py        # SQLite Relational Schema (Domains, Subdomains, IPs, Services, Vulns, PoCs)
│       └── storage.py       # DatabaseManager Persistence & Query Layer
├── modules/                 # Plug-and-Play Intelligence Collectors
│   ├── base.py              # BaseModule Abstract Interface & Common Methods
│   ├── crtsh.py             # Certificate Transparency Subdomain Enumeration
│   ├── reverse_whois.py     # Reverse WHOIS (Hybrid WhoisFreaks + Free Fallback)
│   ├── shodan.py            # Shodan Host, DNS, Range & Query Scanner
│   ├── censys.py            # Censys Platform API v3 Asset & Host Intelligence (CenQL)
│   ├── masscan.py           # High-Speed Active Port Scanner & Banner Grabbing Runner
│   ├── nuclei.py            # Asynchronous Nuclei Vulnerability Scanner Engine
│   ├── nvd.py               # NVD 2.0 (CVSS/CWE) + EPSS Probability + CISA KEV
│   └── exploitdb.py         # ExploitDB (searchsploit) & GitHub PoC Collector
├── reporters/               # Report Generation Subsystem
│   ├── html_reporter.py     # Standalone Styled HTML Exporter (Browser & Print-Ready)
│   ├── json_reporter.py     # Formatted JSON Exporter
│   └── markdown_reporter.py # Executive Markdown Exporter
├── web/                     # Interactive EASM Dashboard Subsystem
│   ├── api/                 
│   │   ├── graph_builder.py # Cytoscape Graph Topology & Target-Root Relationship Builder
│   │   └── routes.py        # FastAPI Endpoints (/databases, /summary, /graph, /assets, /export)
│   ├── static/              
│   │   ├── css/             # Responsive Dashboard Styles (Dark Theme, Drawer, Breakpoints)
│   │   ├── js/              # Cytoscape Graph Engine, Scoped Lead Selector, Filters & Inspector
│   │   └── index.html       # Single Page Application UI
│   ├── process_manager.py   # Background Daemon Server Manager (PID/Status control)
│   └── server.py            # Asynchronous FastAPI & Uvicorn Server
├── utils/                   
│   ├── http.py              # Centralized Async HTTPX Client (Retries, Limits & Headers)
│   └── logger.py            # Rich Console Theme, Colored Risk Badges & Tables
├── tests/                   # Pytest Unit & Integration Test Suite
└── pyproject.toml           # Modern Packaging & Dependency Definition
```

---

## 🧪 Testing

Run the test suite with `pytest`:
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
<br />
<sub>Developed for <b><a href="https://detecti.com.br" target="_blank">DetecTI Security</a></b></sub>

Feel free to open Issues or submit Pull Requests to contribute!
