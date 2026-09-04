# DetecTI - Cyber Lead Intelligence

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
- **Explore Leads:** Abre um modal interativo translúcido no centro da tela com uma **Barra de Pesquisa em Tempo Real** integrada. A partir dele, você pode pesquisar, expandir (Expand All), contrair (Collapse All) ou selecionar individualmente quais elementos passivos você deseja projetar no grafo.
- **Fechamento Ágil:** O modal fecha automaticamente se você clicar em qualquer lugar vazio do canvas ou pressionar a tecla `ESC`.
- **Auto-Select Inteligente:** Se a varredura inicial encontrar um escopo pequeno (50 leads ou menos), a ferramenta fará o auto-selecionamento preventivo e já renderizará a ramificação completa no primeiro carregamento.
- **Sanitização e Hidratação de Alvos:** URLs inseridas via CLI são estritamente sanitizadas para FQDNs puros para evitar duplicidade. Alvos explícitos são hidratados e auto-renderizados no grafo independentemente da reinicialização da sessão. 

### 🔍 HUD de Pesquisa
- A barra de pesquisa ("Search nodes") está ancorada como um HUD (Heads-Up Display) no canto superior esquerdo do próprio canvas. Isso permite filtrar IPs, CVEs ou portas rapidamente sem tirar os olhos do mapa de ataque.

---

## 🎨 Legendas Semânticas e Topologia

O layout hierárquico posiciona as entidades visualmente da esquerda para a direita (ou centro para as bordas), respeitando a taxonomia do ecossistema alvo. As formas geométricas ("shapes") definem estritamente a classe do ativo:

| Formato | Tipo de Ativo | Descrição |
| :--- | :--- | :--- |
| **Logo Flutuante** | **Target Root** | O alvo inicial da varredura, representado pelo logo do DetecTI no centro. |
| **Diamante** (`diamond`) | **Domínio** | Domínios base mapeados na infraestrutura. |
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

