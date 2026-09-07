# 🧠 AGY_CONTEXT.md — DetecTI Security & EASM Engine Context

> **Last Updated:** 2026-09-04 (UI Responsiveness & Target UUID Fixes)
> **Primary Maintainer:** DetecTI Security Engineering  
> **Repositories Tracked:**
> - `/home/ls4ss/dev/DetecTI-CLI` (`https://github.com/detectisec/DetecTI-CLI`)
> - `/home/ls4ss/dev/detectisec.github.io` (`https://github.com/detectisec/detectisec.github.io`)
> - `/home/ls4ss/dev/ls4ss.github.io` (`https://github.com/ls4ss/ls4ss.github.io`)

---

## 📌 Executive Summary & Architecture Overview

**DetecTI-CLI** is an enterprise-grade External Attack Surface Management (EASM) and Cyber Lead Intelligence engine built on Python 3.11+, FastAPI, SQLite, and Cytoscape.js. It acts as the primary technical execution engine for the proprietary **R.A.D.A.R. Framework**.

### 🌐 Key Repositories & Paths
| Directory | Repo Name | Role / Content |
|---|---|---|
| `/home/ls4ss/dev/DetecTI-CLI` | `DetecTI-CLI` | Core Python CLI engine, SQLite persistence, Masscan/Nuclei wrappers, FastAPI server (`detecti-cli hound`), Cytoscape.js Web Dashboard. |
| `/home/ls4ss/dev/detectisec.github.io` | `detectisec.github.io` | Official institutional website and documentation (`/docs/detecti-cli/` [PT/EN] and `/docs/radar/` [PT/EN]). |
| `/home/ls4ss/dev/ls4ss.github.io` | `ls4ss.github.io` | Personal portfolio, certifications, and technical tools (HasHex decoder). |

---

## 🛠️ Core Technical Rules & Business Logic

### 1. 🎯 Host-Centric & Target-Driven Architecture (Completed)
- **Host-Centric Core Topology:** Passive enumeration domains and subdomains are encapsulated directly as rich metadata inside the Host IP nodes (`Associated FQDNs & VHosts`) and in the `target_root` DNS inventory accordion.
- **Target-Driven Node Spawning:** FQDNs only spawn as independent diamond nodes on the canvas if they are explicitly marked as active scan targets (`Set as Target (FQDN)`).
- **Relational Path:**
  - Standard Host: `target_root ──(CONTAINS_TARGET)──► Host IP ──(EXPOSES)──► Services ──(HAS_VULN)──► CVEs`
  - Explicit FQDN Target: `target_root ──(CONTAINS_TARGET)──► FQDN Target ──(RESOLVES_TO)──► Host IP ──(EXPOSES)──► Services ──(HAS_VULN)──► CVEs`
- **Asset Inspector DNS Inventory:** The `target_root` inspector contains accordions `🌐 Enumerated Domains (X)` and `🏷️ Enumerated Subdomains (Y)` with real-time filtering, single/bulk copy, and direct `Target` toggles.

### 2. 🛡️ Mandatory "Confirmed Active" Nuclei Pre-Scan Rule on IPs
- **Rule:** Nuclei **strictly** executes vulnerability templates against IP endpoints and ports marked as `Confirmed Active` (`verified_active === true` / `sources` containing `"Masscan"`).
- **Targeted Pre-Scan:** If a target IP has unverified passive ports in the SQLite database (e.g. from Shodan/Censys), Nuclei **automatically requests Masscan to verify strictly those passive ports**.
- **No Blind Top 100:** Nuclei **never** runs blind `--top-ports 100` scans if no passive ports are present.
- **Smart Skip:** If no passive ports exist or if 0 ports respond after pre-scan, Nuclei skips execution with an explicit reason logged in the live console.

### 3. ⚡ Masscan Smart Port Exclusion & 2-Phase Pipeline
- **Smart Port Exclusion:** In any Masscan scan profile (Top 100, Web Ports, All Ports, Custom), any port already marked as `Confirmed Active` is automatically excluded from the scan payload. If 100% of requested ports are already active, the scan is skipped with an explanatory log.
- **2-Phase Pipeline for All Ports (`0-65535`):**
  - **Phase 1 (Immediate High Priority):** Scans only unverified passive ports associated with the target IP. Provides visual confirmation in the graph within 1-2 seconds.
  - **Phase 2 (Residual 65,535-Port Sweep):** Sweeps remaining unexplored ports, omitting active and Phase 1 tested ports.

### 4. 🧹 Multi-Source Strict Service Deduplication & Auto-Cleanup
- **Deduplication Key:** Strictly enforced on `(ip_id, port, protocol)` across passive recon and active scanning.
- **Source Merging:** Merges provenance lists (e.g. `["Shodan", "Censys", "Masscan", "Nuclei"]`), enriches banners and version details, and prevents duplicate rows in the `services` table.
- **Graph Consolidation:** `GraphBuilder._build_service_nodes` enforces a 1:1 service node representation per port on Cytoscape.
- **Automatic DB Migration (`_deduplicate_services`):** `DatabaseManager._init_database` cleans legacy duplicates on startup, seamlessly re-linking vulnerability records to primary service IDs.

### 5. 🎯 3D EASM Risk Matrix (Threat Intelligence & Mathematical Formulation)
A vulnerability only renders in the priority route if it strictly satisfies the **Logical Conjunction of the 3 Dimensions**:
$$\text{3D Visibility} = \text{Dim 1 (Active Asset)} \land \text{Dim 2 (Technical Impact)} \land [(\text{CISA KEV}) \lor (\text{FIRST EPSS} \ge 20\%) \lor (\text{Public PoC})]$$

#### The 3 Core Dimensions:
1. **Dimensão 1 (Exposição Ativa & Rastreabilidade):** The vulnerability must be tied to a verified active network socket (`service`, `http`, `https`) with confirmed traffic (`verified_active === true`).
2. **Dimensão 2 (Impacto Técnico Nominal):** Critical (CVSS $\ge 9.0$) or High (CVSS $7.0 - 8.9$).
3. **Dimensão 3 (Ameaça Real & Armamento / Disjunção Lógica):** Satisfies at least one of:
   - **CISA KEV Catalog:** Confirmed exploitation in the wild.
   - **FIRST EPSS $\ge 20\%$:** High predictive exploitation probability within 30 days.
   - **Functional Public Weaponization:** Public exploit in Exploit-DB or verified GitHub PoC repository.

---

### 6. 🎨 Graph Topology, Semantics & Visual Design

#### Node Semantics:
| Type | Shape | Color | Operational Meaning |
|---|---|---|---|
| **Target Root** | Squircle (1:1) w/ Terminal Icon | Purple (`#8C52FF`) • Neon Cyan border 3px | The root of the entire graph tree and the origin point from which the initial query was launched. Acts as the central scope anchor, synthesizing the entire attack surface structure in its metadata. Right-click to orchestrate Leads. |
| **FQDN Target** | Ellipse | Turquoise (`#4ecdc4`) • Border `#3aa39c` | Explicit domain/subdomain materialized on canvas when marked as active scan target (`Set as Target (FQDN)`). |
| **Host / IP** | Rectangle | Purple (`#9b59b6`) • Border `#8e44ad` | IPv4/IPv6 host infrastructure with `🌐 N FQDNs` metadata chip. |
| **Target Node (IP/FQDN)** | *Asset Shape* | *Asset Color* + Neon Cyan (`#00f0ff`) Outline | Asset marked as active scan target (`.is-target`). |
| **Service (Passive)** | Hexagon | Dark Slate (`#1e293b`) • Dashed Amber (`#f59e0b`) | Port/Service awaiting active confirmation. |
| **Service (Active)** | Hexagon | Emerald Green (`#27ae60`) • Solid Green (`#2ecc71`) | Port actively confirmed open via Masscan. |
| **Vulnerability (CVE)** | Diamond | Red (`#ef4444`) / Dynamic by Severity | Security vulnerability finding. |
| **CISA KEV** | Diamond | Crimson (`#ff1744`) • White border + Glow | Actively exploited vulnerability. |
| **Service Cluster** | Round-Hexagon | Burnt Orange (`#d35400`) • Dashed border | Collapsible group for >15 ports. |
| **Vuln Cluster** | Round-Diamond | Dark Crimson (`#c0392b`) • Dashed border | Collapsible group for multiple CVEs. |

#### Edge Semantics:
| Edge Label | Style | Color & Width | Source $\rightarrow$ Target | Operational Meaning |
|---|---|---|---|---|
| `CONTAINS_TARGET` | Solid | Purple (`#8c52ff`) • 2px | Target Root $\rightarrow$ Host IP / FQDN Target | Connects root target query to in-scope host IPs and explicit FQDN targets. |
| `RESOLVES_TO` | Solid | Turquoise (`#4ecdc4`) • 1.5px | FQDN Target $\rightarrow$ Host IP | Authoritative DNS resolution linking materialized FQDN targets to physical IP nodes. |
| `EXPOSES` (Passive) | Dotted | Emerald Green (`#2ecc71`) • 2px | Host IP $\rightarrow$ Passive Service | Unverified passive port discovery. |
| `EXPOSES` (Active) | Solid | Emerald Green (`#2ecc71`) • 2.5px | Host IP $\rightarrow$ Confirmed Active Service | Actively validated open port via Masscan. |
| `HAS_VULN` | Dotted | Dynamic Severity (`#ef4444`, `#f97316`, `#eab308`, `#3b82f6`) | Service / Host $\rightarrow$ CVE | Vulnerability association dynamically color-coded by severity. |

---

### 7. 🎛️ Lead Selector 3D Scoring & State Lifecycle
- **Composite 3D Risk Score:**
$$\begin{aligned}
\text{Lead 3D Score} &= (\text{KEVs} \times 1{,}000{,}000) \\
&+ (\text{PoCs/Exploits} \times 200{,}000) \\
&+ (\text{High EPSS}_{\ge 20\%} \times 100{,}000) + (\text{Max EPSS} \times 50{,}000) \\
&+ (\text{Criticals} \times 50{,}000) + (\text{Highs} \times 20{,}000) \\
&+ (\text{Verified Active Services} \times 5{,}000) \\
&+ (\text{Total Vulns} \times 1{,}000) + (\text{Total Services} \times 100)
\end{aligned}$$
- **Graph-First UX & Floating Modal:** The Lead Selector is no longer in the sidebar. It is now an interactive, translucent floating modal triggered by right-clicking the `target_root` node ("Explore Leads...").
- **Intelligent Auto-Select (< 50):** If the initial scan discovers a very small footprint (50 leads or less), the engine will preemptively select and render them all upon the first dashboard load, avoiding unnecessary manual clicks.
- **Unchecked by Default (> 50):** For larger footprints, the modal starts completely clean to prevent canvas clutter, allowing granular selection.
- **Post-Scan Selection Preservation:** When background Masscan or Nuclei scans complete, active lead selections are preserved (`preserveSelection = true`), allowing newly discovered open ports, services, and CVEs to materialize immediately.

---

### 8. 🔍 Search Nodes Indexing & FQDN Match Flow
- **Canvas HUD:** The Search component is now a floating HUD in the top-left of the canvas, maximizing tactical screen real estate.
- **Root Target Query Search (e.g. `vila11.com.br`):** Matches `target_root`, keeping all child IP branches visible.
- **Specific Subdomain Search (e.g. `crm.vila11.com.br`):**
  - Scans `data.fqdns` on Host IP nodes.
  - Matches the physical IP node that resolves that FQDN.
  - Isolates and renders the single-lineage attack vector: `target_root ──► IP (crm.vila11.com.br) ──► Services ──► Vulns`.
- **Search Clearance:** Backspacing or clicking the clear search button (`✕`) immediately restores all checked leads.

---

### 9. ✨ Universal Copy & Target UX Feedback
- **Universal Copy Transitions (`copyTextList`):**
  - Instant button visual transition to emerald green background with checkmark icon (`✓ Copied!`) for 1.8 seconds.
  - System toast notification confirmation (`Copied '...' to clipboard`).
  - Fallback via hidden `textarea` if `navigator.clipboard` is restricted.
- **Target Affirmation Notifications:**
  - Single Target Set: `🎯 Target set: <item>` (Success Toast).
  - Single Target Remove: `Target removed: <item>` (Info Toast).
  - Bulk Target Set: `🎯 Marked N target(s)` (Success Toast).
  - Bulk Target Remove: `Removed N target(s) from scan list` (Info Toast).
  - Clear All Targets: `Cleared all scan targets` (Info Toast).

---

### 10. 🌲 Semantic Hierarchical Layout Engine (Top-Down & Left-Right)
- **Target Root Persistence & Auto-Centering:** The `target_root` is permanently anchored and mathematically centered (`(minY + maxY) / 2`) relative to the spread of the graph.
- **Top-Down Default (with Left-Right Option):** The layout generates 2D coordinates (X, Y) naturally in a Left-Right direction. By default, the engine swaps X and Y coordinates (`x: pos.y, y: pos.x`) right before rendering to create a vertical **Top-Down** flow, which is the system default. Users can toggle back to Left-Right via the UI.
- **Tier Boundaries & Layout Flow:**
  - `Tier 1 (T1): Domains (x=280)`
  - `Tier 2 (T2): Subdomains`
  - `Tier 3 (T3): Host IPs`
  - `Tier 4 (T4): Services`
  - `Tier 5 (T5): Vulnerabilities`
- **10-Nodes Per Fileira Limit (Unified Grid Math):**
  - All nodes are packed into strict grids with a hard limit of `rows = 10` per horizontal line (Top-Down) or column (Left-Right).
  - This prevents the graph from growing infinitely in a single axis, efficiently packing nodes side-by-side using `cCol = Math.floor(idx / 10)` and `cRow = idx % 10`.
- **Anti-Overlap Cascading Sub-Tree Shift:**
  - Nodes with children (e.g. Subdomains with IPs) cannot share the same geometric grid lineage without their children overlapping in the next tier.
  - To solve this mathematically, the algorithm utilizes a **Sub-Tree Cascading Offset** (`xOffset`).
  - When a node is shifted into column `cCol` due to the 10-node limit, it multiplies that shift (`cCol * 350`) and propagates it down to all its descendants. 
  - Result: The child IPs do not form a single flat line. They cascade into distinct geometric blocks, guaranteeing **zero collisions** between adjacent branches.
- **Topological Sorting (Unresolved vs Resolved):**
  - During `placeChildren` iteration, nodes without children (Unresolved Subdomains) are sorted first (`idx = 0..N`). They pack into the first columns (`cCol = 0, 1`), appearing visually in the "primeiras fileiras" (top rows) near their parent Domains.
  - Nodes with children (Resolved Subdomains) are sorted last. They get pushed to higher columns (`cCol = 2, 3..`), forcing them into the "fileiras mais abaixo" (bottom rows), securely anchored close to the IP tier.

---


### 13. 📱 UI/UX Responsiveness & Target Management Integrity
- **Explore Leads & Cytoscape Target Root:** 
  - The `target_root` node visually renders as a floating DetecTI logo on a dark void background (`#0D0E12`) rather than a standard geometric box.
  - The Explore Leads floating modal supports real-time search filtering, and handles viewport boundaries dynamically (`max-width: 90vw`).
- **Strict UUID Normalization in Bulk Actions:** Internal target selections (mass actions like "Target All Leads" or Context Menus) are strictly passed through `normalizeTargetId(target)` which translates database UUIDs back into raw FQDN/IP strings before inserting them into active state (Target Management).
- **Ingestion-Time URL Sanitization:** Incoming targets from passive enumeration tools are vigorously sanitized (stripping `http://`, `https://`, paths, ports) at the `storage.py` choke point *before* hitting the database, preventing duplicate FQDN entries (e.g. `https://vila11.com.br` vs `vila11.com.br`).


### 14. 🛑 AGY_CONTEXT Exclusion Rule
- **NEVER COMMIT THIS FILE:** The `AGY_CONTEXT.md` file is strictly for local AI context synchronization and is ignored by `.gitignore`. It contains proprietary agentic memory and should **never** be added, committed, or pushed to any git repository.

## 🧪 Testing & Daemon Control Commands

```bash
# Check daemon status
cd /home/ls4ss/dev/DetecTI-CLI && ./detecti-cli hound status

# Stop and start daemon
cd /home/ls4ss/dev/DetecTI-CLI && ./detecti-cli hound stop && ./detecti-cli hound start

# Run full backend test suite in DetecTI-CLI
cd /home/ls4ss/dev/DetecTI-CLI && pytest

# Check git status across all 3 repositories
for d in /home/ls4ss/dev/detectisec.github.io /home/ls4ss/dev/ls4ss.github.io /home/ls4ss/dev/DetecTI-CLI; do
  echo "=== Repo: $d ==="
  git -C "$d" status -sb
done
```


## Terminologia do Usuário
*   **"Documentação institucional"** ou **"Documentação oficial"**: Refere-re à documentação hospedada no site oficial (repositório `detectisec.github.io`). Quando solicitado a atualizar a documentação oficial, os arquivos a serem editados não são o `README.md` local, mas sim os arquivos HTML na pasta `/home/ls4ss/dev/detectisec.github.io/docs/detecti-cli/` (como `en.html` e `index.html`).

## Segurança e Autenticação (Dashboard JWT)
*   **Armazenamento de Chave**: O JWT `SECRET_KEY` **não** usa fallback hardcoded em código fonte de produção. Ele é derivado da senha do Admin configurada via `./detecti-cli setup` e persistido exclusivamente no arquivo `.env` local (`JWT_SECRET_KEY=...`).
*   **Acesso e Cookies**: A Dashboard (web/api) possui endpoints totalmente bloqueados (via dependência global do FastAPI `get_current_user`). O token de autenticação é assinado (HMAC-SHA256) e devolvido para o front-end na forma de um cookie `HttpOnly` com expiração rígida de 30 minutos (por questões rigorosas de segurança na manipulação de vulnerabilidades sensíveis do alvo). 
*   **Logout Mechanism**: O front-end dispõe de um botão "Terminate Session" (localizado no footer do `.sidebar`) que realiza um `POST /api/v1/auth/logout`, instruindo o back-end a expurgar o cookie, seguido de um reload forçado da página (levando o usuário instantaneamente de volta ao `login.html`).
*   **Gerenciamento do config.sqlite**: O banco de autenticação oficial dos dashboards fica hospedado estritamente no root data-path `data/config.sqlite` (isolado de `data/dbs/` para impedir que o front-end liste-o acidentalmente como um projeto/target SQLite passível de scan).

### 15. 🛑 Regra de Exclusão de Arquivos Temporários/Desenvolvimento
Todo e qualquer arquivo, script (ex: `fix_*.py`, `patch_*.py`, `update_*.py`) ou código criado para testes pontuais, correções automatizadas ou fluxos criados para uso exclusivo e temporário do ambiente de desenvolvimento **NÃO DEVEM** subir para a branch principal (`main`) e **NEM SER COMITADOS**. 
Esses rascunhos descartáveis devem ser sumariamente apagados após cumprirem sua função ou serem criados em pastas de rascunhos temporárias e não-rastreadas pelo Git.

### Release & Versioning (PyPI)
- **Single Source of Truth**: The project version is strictly controlled by `pyproject.toml` (`version = "X.Y.Z"`). 
- The application runtime (`detecti-cli version`) dynamically reads this version using `importlib.metadata`. Never hardcode version strings in Python files.
- When fixing bugs or pushing new features destined for PyPI, always bump the `version` field in `pyproject.toml` and instruct the user to create a matching GitHub Release (`vX.Y.Z`) to trigger the deployment.
