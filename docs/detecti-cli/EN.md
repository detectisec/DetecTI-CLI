# DetecTI - Cyber Lead Intelligence

Welcome to the official documentation for the **DetecTI-CLI** visual architecture and Graph-First User Experience (UX).

DetecTI is more than just a command-line tool; it features a powerful interactive Dashboard that materializes passive and active intelligence into a hierarchical, semantic graph.

## 🧭 Graph-First UX & Canvas Interaction

DetecTI's visual interface has been redesigned for an immersive, Graph-First experience, minimizing sidebar clutter to maximize focus on investigation and topology.

### 📍 The Root Node (Target Root)
- **Absolute Persistence:** The central node (`target_root`) acts as the anchor of your scope. Regardless of how many items you hide or collapse on the screen (Collapse All), **this node will never disappear**. 
- **Cinematic Auto-Centering:** If you clear the canvas and leave the Root isolated, the camera will smoothly glide and zoom into it, preventing you from getting lost in the vastness of an empty graph.

### 🎯 Lead Management via Context Menu
- Instead of a text-heavy sidebar, passive discovery of Domains, Subdomains, and IPs is managed directly from the graph.
- **Right-Click** the `target_root` node to open the **Context Menu**.
- **Explore Leads:** Opens an interactive, translucent modal in the center of the screen with an integrated **Real-Time Search Bar**. From there, you can search, expand (Expand All), contract (Collapse All), or individually select which passive elements you wish to project onto the graph.
- **Agile Dismissal:** The modal automatically closes if you click anywhere empty on the canvas or press the `ESC` key.
- **Intelligent Auto-Select:** If the initial scan discovers a small scope (50 leads or less), the tool will preemptively auto-select them and render the full branch structure upon the first load.
- **Target Sanitization & Hydration:** URLs entered via CLI are strictly sanitized into pure FQDNs to prevent duplication. Explicit targets are automatically hydrated and rendered in the graph across dashboard sessions.

### 🔍 Search HUD
- The search bar ("Search nodes") is anchored as a Heads-Up Display (HUD) in the top-left corner of the canvas. This allows you to quickly filter IPs, CVEs, or ports without taking your eyes off the attack map.

---

## 🎨 Semantic Legends & Topology

The hierarchical layout visually positions entities from left to right (or center to edges), strictly respecting the taxonomy of the target ecosystem. The geometric shapes define the asset class:

| Shape | Asset Type | Description |
| :--- | :--- | :--- |
| **Floating Logo** | **Target Root** | The initial scan target, represented by the DetecTI logo in the center. |
| **Diamond** | **Domain** | Base domains mapped in the infrastructure. |
| **Hexagon** | **Subdomain** | Discovered FQDNs subordinate to a Domain. |
| **Ellipse** | **IP Address** | Real hosting infrastructure (Hosts). Passive or active IPs. |
| **Round Rectangle** | **Services / Ports** | Open ports found via Masscan (e.g., TCP 22, TCP 80). |
| **Double Circle** | **Web Service (HTTP/S)** | A service that responded with a valid Web protocol (HTTP/HTTPS). |
| **Cut Hexagon** | **Vulnerability** | Represents a CVE or weakness discovered by Nuclei. |

### 🎯 States & Colors (Active vs Passive)
- **Gray/Dark Blue (Passive):** Assets (Leads) discovered by passive sources (Shodan, CRT.sh, WHOIS) but not yet authorized for active scanning.
- **Glowing Cyan (Active Target):** When you send an asset to "Target Management" (either manually via Context Menu or automatically if <= 50 items), it glows Cyan and displays a red target crosshair. This indicates it is cleared for aggressive scanning (Masscan/Nuclei).

## 🚀 How to Execute the Visual Engine
After performing your passive or active collections with the DetecTI CLI:
1. Start the local web interface.
2. Open the Dashboard in your browser.
3. The panel will read your SQLite database, automatically applying the semantic layout.
4. For large datasets, the `target_root` will be ready in the center waiting for you to right-click to explore and orchestrate your analysis.

