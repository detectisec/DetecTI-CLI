import os

docs_dir = "docs/detecti-cli"
os.makedirs(docs_dir, exist_ok=True)

pt_br = """# DetecTI - Cyber Lead Intelligence

Bem-vindo à documentação oficial da arquitetura visual e da experiência de usuário (UX) Graph-First do **DetecTI-CLI**.

O DetecTI não é apenas uma ferramenta de linha de comando; ele possui um Dashboard interativo poderoso que materializa a inteligência passiva e ativa em um grafo hierárquico e semântico.

## 🧭 UX Graph-First e Interação com o Canvas

A interface visual do DetecTI foi redesenhada para uma experiência imersiva e focada no grafo (Graph-First), minimizando o uso de barras laterais para maximizar o foco na investigação e topologia.

### 📍 O Nó Raiz (Target Root)
- **Persistência Absoluta:** O nó central (`target_root`) funciona como a âncora do seu escopo. Independentemente da quantidade de itens que você oculta ou recolhe na tela (Collapse All), **este nó nunca desaparecerá**. 
- **Auto-Centralização Cinemática:** Caso você limpe o canvas e deixe o Root isolado, a câmera deslizará suavemente e fará um zoom focado nele, evitando que você se perca na imensidão do grafo vazio.

### 🎯 Gestão de Leads via Context Menu
- Ao invés de uma barra lateral cheia de texto, a descoberta passiva de Domínios, Subdomínios e IPs é gerida diretamente pelo grafo.
- **Clique com o Botão Direito** no nó `target_root` para abrir o **Context Menu**.
- **Explore Leads:** Abre um modal interativo translúcido no centro da tela. A partir dele, você pode expandir (Expand All), contrair (Collapse All) ou selecionar individualmente quais elementos passivos você deseja projetar no grafo.
- **Fechamento Ágil:** O modal fecha automaticamente se você clicar em qualquer lugar vazio do canvas ou pressionar a tecla `ESC`.
- **Auto-Select Inteligente:** Se a varredura inicial encontrar um escopo pequeno (50 leads ou menos), a ferramenta fará o auto-selecionamento preventivo e já renderizará a ramificação completa no primeiro carregamento. 

### 🔍 HUD de Pesquisa
- A barra de pesquisa ("Search nodes") está ancorada como um HUD (Heads-Up Display) no canto superior esquerdo do próprio canvas. Isso permite filtrar IPs, CVEs ou portas rapidamente sem tirar os olhos do mapa de ataque.

---

## 🎨 Legendas Semânticas e Topologia

O layout hierárquico posiciona as entidades visualmente da esquerda para a direita (ou centro para as bordas), respeitando a taxonomia do ecossistema alvo. As formas geométricas ("shapes") definem estritamente a classe do ativo:

| Formato | Tipo de Ativo | Descrição |
| :--- | :--- | :--- |
| **Diamante** (`diamond`) | **Domínio / Target Root** | O domínio raiz ou o alvo inicial da varredura. Representa o ápice da hierarquia. |
| **Hexágono** (`hexagon`) | **Subdomínio** | FQDNs descobertos que são subordinados a um Domínio. |
| **Elipse** (`ellipse`) | **Endereço IP** | Infraestrutura real de hospedagem (Hosts). IPs passivos ou ativos. |
| **Quadrado Arredondado** | **Serviços / Portas** | Portas abertas encontradas via Masscan (Ex: TCP 22, TCP 80). |
| **Círculo Duplo** | **Serviço Web (HTTP/S)** | Um serviço que respondeu como protocolo Web válido (HTTP/HTTPS). |
| **Hexágono Vazado** | **Vulnerabilidade** | Representa uma CVE ou fraqueza descoberta pelo Nuclei. |

### 🎯 Estados e Cores (Active vs Passive)
- **Cinza/Azul Escuro (Passive):** Ativos (Leads) que foram descobertos por fontes passivas (Shodan, CRT.sh, WHOIS) mas ainda não foram autorizados para varredura ativa.
- **Ciano Brilhante (Active Target):** Quando você envia um ativo para "Target Management" (seja manualmente via Context Menu ou pelo limite automático de 50 itens), ele se acende na cor Ciano com um ícone de alvo vermelho (Crosshair). Isso indica que ele será alvo de varreduras agressivas (Masscan/Nuclei).

## 🚀 Como Executar o Motor Visual
Após realizar suas coletas passivas ou ativas com o CLI do DetecTI:
1. Inicie a interface web local.
2. Abra o Dashboard no navegador.
3. O painel lerá seu arquivo SQLite, aplicando o layout semântico automaticamente.
4. Caso a base seja volumosa, o `target_root` estará pronto no centro aguardando você clicar com o botão direito para explorar e orquestrar sua análise.

"""

en = """# DetecTI - Cyber Lead Intelligence

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
- **Explore Leads:** Opens an interactive, translucent modal in the center of the screen. From there, you can expand (Expand All), contract (Collapse All), or individually select which passive elements you wish to project onto the graph.
- **Agile Dismissal:** The modal automatically closes if you click anywhere empty on the canvas or press the `ESC` key.
- **Intelligent Auto-Select:** If the initial scan discovers a small scope (50 leads or less), the tool will preemptively auto-select them and render the full branch structure upon the first load.

### 🔍 Search HUD
- The search bar ("Search nodes") is anchored as a Heads-Up Display (HUD) in the top-left corner of the canvas. This allows you to quickly filter IPs, CVEs, or ports without taking your eyes off the attack map.

---

## 🎨 Semantic Legends & Topology

The hierarchical layout visually positions entities from left to right (or center to edges), strictly respecting the taxonomy of the target ecosystem. The geometric shapes define the asset class:

| Shape | Asset Type | Description |
| :--- | :--- | :--- |
| **Diamond** | **Domain / Target Root** | The root domain or initial scan target. Represents the apex of the hierarchy. |
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

"""

with open(f"{docs_dir}/PT-BR.md", "w") as f:
    f.write(pt_br)

with open(f"{docs_dir}/EN.md", "w") as f:
    f.write(en)
