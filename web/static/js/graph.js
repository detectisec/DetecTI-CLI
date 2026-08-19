/**
 * DetecTI-CLI EASM Dashboard - Cytoscape.js Graph Implementation
 */

class EASMDashboard {
    constructor() {
        this.cy = null;
        this.graphData = null;
        this.leads = [];
        this.selectedLeads = new Set();
        this.filters = {
            kev: false,
            highEpss: false,
            critical: false,
            withPocs: false,
            subdomainsOnly: false
        };
        this.searchTerm = '';
        
        // Don't auto-initialize, wait for DOM
    }

    getAvailableLayout() {
        // Check if cose-bilkent is available, fallback to other layouts
        if (typeof cytoscapeCoseBilkent !== 'undefined') {
            return 'cose-bilkent';
        } else if (cytoscape('layout', 'cose')) {
            return 'cose';
        } else {
            return 'breadthfirst';
        }
    }

    getLayoutOptions(layoutName) {
        const baseOptions = {
            animate: true,
            animationDuration: 1000,
            fit: true,
            padding: 50
        };

        switch (layoutName) {
            case 'cose-bilkent':
                return {
                    ...baseOptions,
                    nodeRepulsion: 8000,
                    idealEdgeLength: 100,
                    edgeElasticity: 0.1,
                    nestingFactor: 0.1,
                    gravity: 0.1,
                    numIter: 2500,
                    tile: true,
                    tilingPaddingVertical: 10,
                    tilingPaddingHorizontal: 10
                };
            case 'cose':
                return {
                    ...baseOptions,
                    nodeRepulsion: 400000,
                    idealEdgeLength: 100,
                    edgeElasticity: 100,
                    nestingFactor: 5,
                    gravity: 80,
                    numIter: 1000
                };
            case 'breadthfirst':
                return {
                    ...baseOptions,
                    directed: true,
                    spacingFactor: 1.75,
                    roots: function(nodes) {
                        // Use IP nodes as roots for hierarchical layout (IP -> Domain/Sub -> Services -> Vulns)
                        return nodes.filter(function(node) {
                            return node.data('type') === 'ip';
                        });
                    }
                };
            case 'concentric':
                return {
                    ...baseOptions,
                    concentric: function(node) {
                        return node.degree();
                    },
                    levelWidth: function(nodes) {
                        return 2;
                    }
                };
            case 'grid':
                return {
                    ...baseOptions,
                    rows: undefined,
                    cols: undefined
                };
            default:
                return baseOptions;
        }
    }

    async init() {
        try {
            console.log('Initializing EASM Dashboard...');
            
            // Check if API client is available
            if (!window.api) {
                throw new Error('API client not available');
            }
            
            // Load summary data
            console.log('Loading summary data...');
            await this.loadSummary();
            
            // Load leads data
            console.log('Loading leads data...');
            await this.loadLeads();
            
            // Initialize Cytoscape
            console.log('Initializing Cytoscape...');
            this.initCytoscape();
            
            // Load and render graph
            console.log('Loading graph data...');
            await this.loadGraph();
            
            // Setup event listeners
            console.log('Setting up event listeners...');
            this.setupEventListeners();
            
            // Set the correct default layout in the selector
            this.updateLayoutSelector();
            
            // Hide loading indicator
            const loadingEl = document.getElementById('graph-loading');
            if (loadingEl) {
                loadingEl.style.display = 'none';
            }
            
            console.log('Dashboard initialization complete');
            
        } catch (error) {
            console.error('Failed to initialize dashboard:', error);
            this.showError(`Failed to load dashboard data: ${error.message}`);
        }
    }

    async loadSummary() {
        try {
            console.log('Fetching summary data...');
            const summary = await window.api.getSummary();
            console.log('Summary data received:', summary);
            
            // Update header
            const targetEl = document.getElementById('target-name');
            if (targetEl) {
                targetEl.textContent = summary.target || 'Unknown Target';
            }
            
            // Update metrics with safe element access
            const updateMetric = (id, value) => {
                const el = document.getElementById(id);
                if (el) {
                    el.textContent = value || 0;
                } else {
                    console.warn(`Element not found: ${id}`);
                }
            };
            
            updateMetric('domains-count', summary.total_domains);
            updateMetric('subdomains-count', summary.total_subdomains);
            updateMetric('ips-count', summary.total_ips);
            updateMetric('services-count', summary.open_services);
            updateMetric('vulns-count', summary.total_vulnerabilities);
            updateMetric('kev-count', summary.cisa_kev_count);
            
            console.log('Summary data loaded successfully');
            
        } catch (error) {
            console.error('Failed to load summary:', error);
            throw error; // Re-throw to be caught by init()
        }
    }

    async loadLeads() {
        try {
            console.log('Fetching leads data...');
            this.leads = await window.api.getLeads();
            console.log('Leads data received:', this.leads);
            
            this.renderLeadSelector();
            
            console.log('Leads data loaded successfully');
            
        } catch (error) {
            console.error('Failed to load leads:', error);
            throw error; // Re-throw to be caught by init()
        }
    }

    renderLeadSelector() {
        const leadList = document.getElementById('lead-list');
        if (!leadList) return;

        if (this.leads.length === 0) {
            leadList.innerHTML = '<div class="lead-loading">No leads found</div>';
            return;
        }

        leadList.innerHTML = '';

        this.leads.forEach(lead => {
            const leadItem = document.createElement('div');
            leadItem.className = 'lead-item';
            leadItem.dataset.leadId = lead.id;

            // Build badges
            const badges = [];
            if (lead.vuln_count > 0) {
                badges.push('<span class="lead-badge cve">CVE</span>');
            }
            if (lead.poc_count > 0) {
                badges.push('<span class="lead-badge poc">PoC</span>');
            }
            if (lead.has_kev) {
                badges.push('<span class="lead-badge kev">KEV</span>');
            }
            if (lead.has_critical) {
                badges.push('<span class="lead-badge critical">CRIT</span>');
            }

            // Build stats
            let stats = '';
            if (lead.type === 'ip') {
                stats = `${lead.service_count} services, ${lead.vuln_count} vulns`;
            } else if (lead.type === 'domain') {
                stats = `${lead.ip_count} IPs, ${lead.service_count} services, ${lead.vuln_count} vulns`;
            }

            leadItem.innerHTML = `
                <div class="lead-checkbox"></div>
                <div class="lead-info">
                    <div class="lead-name">${lead.display_name}</div>
                    <div class="lead-type">${lead.type}</div>
                    <div class="lead-badges">${badges.join('')}</div>
                    <div class="lead-stats">${stats}</div>
                </div>
            `;

            leadItem.addEventListener('click', () => {
                this.toggleLead(lead.id);
            });

            leadList.appendChild(leadItem);
        });
    }

    toggleLead(leadId) {
        const leadItem = document.querySelector(`[data-lead-id="${leadId}"]`);
        if (!leadItem) return;

        if (this.selectedLeads.has(leadId)) {
            this.selectedLeads.delete(leadId);
            leadItem.classList.remove('selected');
        } else {
            this.selectedLeads.add(leadId);
            leadItem.classList.add('selected');
        }

        this.applyLeadFilter();
    }

    selectAllLeads() {
        this.leads.forEach(lead => {
            this.selectedLeads.add(lead.id);
            const leadItem = document.querySelector(`[data-lead-id="${lead.id}"]`);
            if (leadItem) {
                leadItem.classList.add('selected');
            }
        });
        this.applyLeadFilter();
    }

    deselectAllLeads() {
        this.selectedLeads.clear();
        document.querySelectorAll('.lead-item').forEach(item => {
            item.classList.remove('selected');
        });
        this.applyLeadFilter();
    }

    applyLeadFilter() {
        if (!this.cy) return;

        // If no leads are selected, hide all nodes (default behavior)
        if (this.selectedLeads.size === 0) {
            this.cy.nodes().hide();
            this.cy.edges().hide();
            return;
        }

        // Show all nodes first
        this.cy.nodes().show();
        this.cy.edges().show();

        // Get selected lead names
        const selectedLeadNames = new Set();
        this.leads.forEach(lead => {
            if (this.selectedLeads.has(lead.id)) {
                selectedLeadNames.add(lead.name);
            }
        });

        // Build a set of nodes that should be visible (lead nodes + their entire sub-tree)
        const visibleNodes = new Set();

        // First pass: Find all lead nodes that are selected
        this.cy.nodes().forEach(node => {
            const nodeData = node.data();
            
            // Check if this is a selected lead node
            if (nodeData.type === 'ip' && selectedLeadNames.has(nodeData.ip)) {
                visibleNodes.add(node.id());
            } else if ((nodeData.type === 'domain' || nodeData.type === 'subdomain') && selectedLeadNames.has(nodeData.name)) {
                visibleNodes.add(node.id());
            }
        });

        // Second pass: Add all nodes connected to selected leads (services, vulnerabilities, etc.)
        const addConnectedNodes = (nodeId) => {
            const node = this.cy.getElementById(nodeId);
            if (!node.length) return;
            
            // Add all neighbors (connected nodes)
            const neighbors = node.neighborhood().nodes();
            neighbors.forEach(neighbor => {
                const neighborId = neighbor.id();
                if (!visibleNodes.has(neighborId)) {
                    visibleNodes.add(neighborId);
                    // Recursively add their connections (for vulnerability -> exploit chains)
                    addConnectedNodes(neighborId);
                }
            });
        };

        // Add all connected nodes for each selected lead
        visibleNodes.forEach(nodeId => {
            addConnectedNodes(nodeId);
        });

        // Third pass: Hide all nodes that are not in the visible set
        this.cy.nodes().forEach(node => {
            if (!visibleNodes.has(node.id())) {
                node.hide();
            }
        });

        // Hide edges connected to hidden nodes
        this.cy.edges().forEach(edge => {
            const source = edge.source();
            const target = edge.target();
            if (source.hidden() || target.hidden()) {
                edge.hide();
            }
        });

        // Apply other filters on top of lead filter
        this.applyFilters();
    }

    initCytoscape() {
        // Register the cose-bilkent layout extension if available
        if (typeof cytoscapeCoseBilkent !== 'undefined') {
            cytoscape.use(cytoscapeCoseBilkent);
        }
        
        this.cy = cytoscape({
            container: document.getElementById('cy'),
            
            style: [
                // Domain nodes
                {
                    selector: 'node[type="domain"]',
                    style: {
                        'background-color': '#00d4ff',
                        'label': 'data(label)',
                        'color': '#ffffff',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'font-size': '12px',
                        'font-weight': 'bold',
                        'width': '60px',
                        'height': '60px',
                        'shape': 'ellipse',
                        'border-width': '2px',
                        'border-color': '#0099cc'
                    }
                },
                
                // Subdomain nodes
                {
                    selector: 'node[type="subdomain"]',
                    style: {
                        'background-color': '#4ecdc4',
                        'label': 'data(label)',
                        'color': '#ffffff',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'font-size': '10px',
                        'width': '50px',
                        'height': '50px',
                        'shape': 'ellipse',
                        'border-width': '1px',
                        'border-color': '#3aa39c'
                    }
                },
                
                // IP address nodes
                {
                    selector: 'node[type="ip"]',
                    style: {
                        'background-color': '#9b59b6',
                        'label': 'data(label)',
                        'color': '#ffffff',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'font-size': '10px',
                        'font-weight': 'bold',
                        'width': '55px',
                        'height': '55px',
                        'shape': 'rectangle',
                        'border-width': '2px',
                        'border-color': '#8e44ad'
                    }
                },
                
                // Service nodes
                {
                    selector: 'node[type="service"], node[type="http"], node[type="https"]',
                    style: {
                        'background-color': '#f39c12',
                        'label': 'data(label)',
                        'color': '#ffffff',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'font-size': '9px',
                        'width': '45px',
                        'height': '45px',
                        'shape': 'hexagon',
                        'border-width': '1px',
                        'border-color': '#e67e22'
                    }
                },
                
                // HTTPS services (special styling)
                {
                    selector: 'node[type="https"]',
                    style: {
                        'background-color': '#27ae60',
                        'border-color': '#229954',
                        'border-width': '2px'
                    }
                },
                
                // Vulnerability nodes
                {
                    selector: 'node[type="vulnerability"]',
                    style: {
                        'background-color': '#e74c3c',
                        'label': 'data(cve_id)',
                        'color': '#ffffff',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'font-size': '9px',
                        'font-weight': 'bold',
                        'width': '50px',
                        'height': '50px',
                        'shape': 'diamond',
                        'border-width': '2px',
                        'border-color': '#c0392b'
                    }
                },
                
                // High severity vulnerabilities
                {
                    selector: 'node[risk_level="high"]',
                    style: {
                        'background-color': '#ff6b6b',
                        'border-color': '#ff5252',
                        'border-width': '2px'
                    }
                },
                
                // Medium severity vulnerabilities
                {
                    selector: 'node[risk_level="medium"]',
                    style: {
                        'background-color': '#ff8c00',
                        'border-color': '#ff7f00',
                        'border-width': '2px'
                    }
                },
                
                // Low severity vulnerabilities
                {
                    selector: 'node[risk_level="low"]',
                    style: {
                        'background-color': '#2ed573',
                        'border-color': '#20bf6b',
                        'border-width': '2px'
                    }
                },
                
                // Critical vulnerabilities (darker red with pulsing animation)
                {
                    selector: 'node[risk_level="critical"]',
                    style: {
                        'background-color': '#8b0000',
                        'border-color': '#dc143c',
                        'border-width': '4px'
                    }
                },
                
                // CISA KEV vulnerabilities (special glow)
                {
                    selector: 'node[is_cisa_kev="true"]',
                    style: {
                        'background-color': '#ff1744',
                        'border-color': '#ffffff',
                        'border-width': '3px',
                        'box-shadow': '0 0 20px #ff1744'
                    }
                },
                
                // Edges
                {
                    selector: 'edge',
                    style: {
                        'width': '2px',
                        'line-color': '#555555',
                        'target-arrow-color': '#555555',
                        'target-arrow-shape': 'triangle',
                        'curve-style': 'bezier',
                        'label': 'data(label)',
                        'font-size': '8px',
                        'color': '#888888',
                        'text-rotation': 'autorotate'
                    }
                },
                
                // Vulnerability edges (red) - thicker to emphasize the service->vuln relationship
                {
                    selector: 'edge[label="HAS_VULN"]',
                    style: {
                        'line-color': '#e74c3c',
                        'target-arrow-color': '#e74c3c',
                        'width': '4px',
                        'line-style': 'solid'
                    }
                },
                
                // Service exposure edges (orange)
                {
                    selector: 'edge[label="EXPOSES"]',
                    style: {
                        'line-color': '#f39c12',
                        'target-arrow-color': '#f39c12',
                        'width': '3px'
                    }
                },
                
                // Domain relationship edges
                {
                    selector: 'edge[label="HAS_SUBDOMAIN"]',
                    style: {
                        'line-color': '#4ecdc4',
                        'target-arrow-color': '#4ecdc4',
                        'width': '2px'
                    }
                },
                
                {
                    selector: 'edge[label="BELONGS_TO"]',
                    style: {
                        'line-color': '#9b59b6',
                        'target-arrow-color': '#9b59b6',
                        'width': '2px'
                    }
                },
                
                // Selected nodes
                {
                    selector: 'node:selected',
                    style: {
                        'border-width': '4px',
                        'border-color': '#ffffff',
                        'box-shadow': '0 0 20px #00d4ff'
                    }
                }
            ],
            
            layout: {
                name: this.getAvailableLayout(),
                animate: true,
                animationDuration: 1000,
                fit: true,
                padding: 50
            }
        });
    }

    async loadGraph() {
        try {
            console.log('Fetching graph data...');
            this.graphData = await window.api.getGraphData();
            console.log('Graph data received:', this.graphData);
            
            if (this.graphData && this.graphData.elements) {
                console.log(`Adding ${this.graphData.elements.nodes?.length || 0} nodes and ${this.graphData.elements.edges?.length || 0} edges`);
                
                this.cy.elements().remove();
                this.cy.add(this.graphData.elements);
                
                // Apply lead filter first (starts with empty selection = hidden graph)
                this.applyLeadFilter();
                
                // Run layout
                const layoutName = this.getAvailableLayout();
                const layoutOptions = this.getLayoutOptions(layoutName);
                const layout = this.cy.layout({ 
                    name: layoutName,
                    ...layoutOptions
                });
                layout.run();
                
                console.log('Graph rendered successfully');
            } else {
                console.warn('No graph elements received');
                this.showError('No graph data available');
            }
            
        } catch (error) {
            console.error('Failed to load graph data:', error);
            throw error; // Re-throw to be caught by init()
        }
    }

    setupEventListeners() {
        // Node click handler
        this.cy.on('tap', 'node', (event) => {
            const node = event.target;
            this.showNodeInspector(node);
        });

        // Background click handler (close inspector)
        this.cy.on('tap', (event) => {
            if (event.target === this.cy) {
                this.closeInspector();
            }
        });

        // Search functionality
        document.getElementById('search-input').addEventListener('input', (e) => {
            this.searchTerm = e.target.value.toLowerCase();
            this.applyFilters();
        });

        document.getElementById('clear-search').addEventListener('click', () => {
            document.getElementById('search-input').value = '';
            this.searchTerm = '';
            this.applyFilters();
        });

        // Lead selector controls
        document.getElementById('select-all-leads').addEventListener('click', () => {
            this.selectAllLeads();
        });

        document.getElementById('deselect-all-leads').addEventListener('click', () => {
            this.deselectAllLeads();
        });

        // Filter checkboxes
        document.getElementById('filter-kev').addEventListener('change', (e) => {
            this.filters.kev = e.target.checked;
            this.applyFilters();
        });

        document.getElementById('filter-high-epss').addEventListener('change', (e) => {
            this.filters.highEpss = e.target.checked;
            this.applyFilters();
        });

        document.getElementById('filter-critical').addEventListener('change', (e) => {
            this.filters.critical = e.target.checked;
            this.applyFilters();
        });

        document.getElementById('filter-with-pocs').addEventListener('change', (e) => {
            this.filters.withPocs = e.target.checked;
            this.applyFilters();
        });

        document.getElementById('filter-subdomains-only').addEventListener('change', (e) => {
            this.filters.subdomainsOnly = e.target.checked;
            this.applyFilters();
        });

        // Control buttons
        document.getElementById('btn-fit').addEventListener('click', () => {
            this.cy.fit();
        });

        document.getElementById('btn-reset-zoom').addEventListener('click', () => {
            this.cy.zoom(1);
            this.cy.center();
        });

        document.getElementById('btn-relayout').addEventListener('click', () => {
            const layoutName = document.getElementById('layout-select').value;
            const layoutOptions = this.getLayoutOptions(layoutName);
            this.cy.layout({ name: layoutName, ...layoutOptions }).run();
        });

        // Layout selector
        document.getElementById('layout-select').addEventListener('change', (e) => {
            const layoutName = e.target.value;
            const layoutOptions = this.getLayoutOptions(layoutName);
            this.cy.layout({ name: layoutName, ...layoutOptions }).run();
        });

        // Inspector close button
        document.getElementById('close-inspector').addEventListener('click', () => {
            this.closeInspector();
        });
    }

    applyFilters() {
        if (!this.cy) return;

        // First apply lead filter (this handles showing/hiding based on selected leads)
        // Only apply other filters if we have visible nodes from lead selection
        if (this.selectedLeads.size === 0) {
            return; // Lead filter already hid everything
        }

        // Apply search filter
        if (this.searchTerm) {
            this.cy.nodes().forEach(node => {
                if (node.hidden()) return; // Skip already hidden nodes
                
                const data = node.data();
                const searchableText = [
                    data.label,
                    data.name,
                    data.ip,
                    data.cve_id,
                    data.service,
                    data.product,
                    data.org,
                    data.country,
                    data.port ? data.port.toString() : ''
                ].filter(Boolean).join(' ').toLowerCase();
                
                if (!searchableText.includes(this.searchTerm)) {
                    node.hide();
                }
            });
        }

        // Apply subdomain-only filter
        if (this.filters.subdomainsOnly) {
            this.cy.nodes().forEach(node => {
                if (node.hidden()) return; // Skip already hidden nodes
                
                const nodeType = node.data('type');
                if (!['subdomain', 'domain'].includes(nodeType)) {
                    node.hide();
                }
            });
        }

        // Apply vulnerability filters
        const hasVulnFilters = this.filters.kev || this.filters.highEpss || this.filters.critical || this.filters.withPocs;
        
        if (hasVulnFilters) {
            this.cy.nodes('[type="vulnerability"]').forEach(node => {
                if (node.hidden()) return; // Skip already hidden nodes
                
                let shouldShow = false;
                
                // Check CISA KEV filter
                if (this.filters.kev && node.data('is_cisa_kev') === true) {
                    shouldShow = true;
                }
                
                // Check high EPSS filter
                if (this.filters.highEpss) {
                    const epssScore = node.data('epss_score') || 0;
                    if (epssScore > 0.5) {
                        shouldShow = true;
                    }
                }
                
                // Check critical severity filter
                if (this.filters.critical && node.data('severity') === 'CRITICAL') {
                    shouldShow = true;
                }
                
                // Check PoCs filter
                if (this.filters.withPocs && node.data('has_pocs') === true) {
                    shouldShow = true;
                }
                
                if (!shouldShow) {
                    node.hide();
                }
            });
        }

        // Hide edges connected to hidden nodes
        this.cy.edges().forEach(edge => {
            const source = edge.source();
            const target = edge.target();
            if (source.hidden() || target.hidden()) {
                edge.hide();
            }
        });
    }

    showNodeInspector(node) {
        const data = node.data();
        const drawer = document.getElementById('inspector-drawer');
        const content = document.getElementById('inspector-content');
        const title = document.getElementById('inspector-title');

        // Set title based on node type
        title.textContent = `${data.type.toUpperCase()}: ${data.label || data.id}`;

        // Build content based on node type
        let html = '';

        if (data.type === 'domain' || data.type === 'subdomain') {
            html = `
                <h4>Domain Information</h4>
                <div class="property">
                    <span class="key">Name:</span>
                    <span class="value">${data.name || data.label}</span>
                </div>
                <div class="property">
                    <span class="key">Type:</span>
                    <span class="value">${data.type}</span>
                </div>
            `;
        } else if (data.type === 'ip') {
            html = `
                <h4>IP Address Information</h4>
                <div class="property">
                    <span class="key">IP Address:</span>
                    <span class="value">${data.ip}</span>
                </div>
                <div class="property">
                    <span class="key">Organization:</span>
                    <span class="value">${data.org || 'Unknown'}</span>
                </div>
                <div class="property">
                    <span class="key">Country:</span>
                    <span class="value">${data.country || 'Unknown'}</span>
                </div>
                <div class="property">
                    <span class="key">ASN:</span>
                    <span class="value">${data.asn || 'Unknown'}</span>
                </div>
            `;
        } else if (data.type === 'service' || data.type === 'http' || data.type === 'https') {
            html = `
                <h4>Service Information</h4>
                <div class="property">
                    <span class="key">Port:</span>
                    <span class="value">${data.port}/${data.protocol}</span>
                </div>
                <div class="property">
                    <span class="key">Service:</span>
                    <span class="value">${data.service || 'Unknown'}</span>
                </div>
                <div class="property">
                    <span class="key">Product:</span>
                    <span class="value">${data.product || 'Unknown'}</span>
                </div>
                <div class="property">
                    <span class="key">Version:</span>
                    <span class="value">${data.version || 'Unknown'}</span>
                </div>
                <div class="property">
                    <span class="key">SSL/TLS:</span>
                    <span class="value">${data.ssl ? 'Yes' : 'No'}</span>
                </div>
            `;
        } else if (data.type === 'vulnerability') {
            const kevBadge = data.is_cisa_kev === true ? '<span class="vulnerability-badge kev">CISA KEV</span>' : '';
            const severityClass = (data.severity || 'unknown').toLowerCase();
            
            // Find connected service to show the relationship
            const connectedService = this.cy.edges(`[target="${data.id}"][label="HAS_VULN"]`).source();
            let serviceInfo = '';
            if (connectedService.length > 0) {
                const serviceData = connectedService.data();
                serviceInfo = `
                <div class="property">
                    <span class="key">Affected Service:</span>
                    <span class="value">${serviceData.port}/${serviceData.protocol} (${serviceData.service || 'Unknown'})</span>
                </div>`;
            }
            
            // Build exploits/PoCs section with GitHub and ExploitDB separation
            let exploitsSection = '';
            if (data.exploits && data.exploits.length > 0) {
                const githubExploits = data.exploits.filter(e => e.source.toLowerCase().includes('github'));
                const exploitdbExploits = data.exploits.filter(e => !e.source.toLowerCase().includes('github'));
                
                exploitsSection = '<h4>Available Exploits & PoCs</h4>';
                
                if (githubExploits.length > 0) {
                    exploitsSection += '<h5 style="color: #00d4ff; margin: 1rem 0 0.5rem 0;">🐙 GitHub PoCs</h5>';
                    githubExploits.forEach(exploit => {
                        const verifiedBadge = exploit.verified ? '<span class="exploit-badge verified">✓ Verified</span>' : '';
                        
                        exploitsSection += `
                        <div class="exploit-item">
                            <div class="exploit-header">
                                <span class="exploit-source github">${exploit.source}</span>
                                ${verifiedBadge}
                            </div>
                            <div class="exploit-title">${exploit.title}</div>
                            <div class="exploit-details">
                                ${exploit.author ? `<span>👤 Author: ${exploit.author}</span>` : ''}
                                ${exploit.date ? `<span>📅 Date: ${exploit.date}</span>` : ''}
                                ${exploit.exploit_type ? `<span>🏷️ Type: ${exploit.exploit_type}</span>` : ''}
                            </div>
                            <div class="exploit-url">
                                <a href="${exploit.url}" target="_blank" rel="noopener">🔗 ${exploit.url}</a>
                            </div>
                        </div>`;
                    });
                }
                
                if (exploitdbExploits.length > 0) {
                    exploitsSection += '<h5 style="color: #e74c3c; margin: 1rem 0 0.5rem 0;">💥 ExploitDB</h5>';
                    exploitdbExploits.forEach(exploit => {
                        const verifiedBadge = exploit.verified ? '<span class="exploit-badge verified">✓ Verified</span>' : '';
                        
                        exploitsSection += `
                        <div class="exploit-item">
                            <div class="exploit-header">
                                <span class="exploit-source exploitdb">${exploit.source}</span>
                                ${verifiedBadge}
                            </div>
                            <div class="exploit-title">${exploit.title}</div>
                            <div class="exploit-details">
                                ${exploit.author ? `<span>👤 Author: ${exploit.author}</span>` : ''}
                                ${exploit.date ? `<span>📅 Date: ${exploit.date}</span>` : ''}
                                ${exploit.exploit_type ? `<span>🏷️ Type: ${exploit.exploit_type}</span>` : ''}
                            </div>
                            <div class="exploit-url">
                                <a href="${exploit.url}" target="_blank" rel="noopener">🔗 ${exploit.url}</a>
                            </div>
                        </div>`;
                    });
                }
            }
            
            html = `
                <h4>Vulnerability Details</h4>
                <div class="property">
                    <span class="key">CVE ID:</span>
                    <span class="value">${data.cve_id}</span>
                </div>
                ${serviceInfo}
                <div class="property">
                    <span class="key">Severity:</span>
                    <span class="value">
                        <span class="vulnerability-badge ${severityClass}">${data.severity}</span>
                        ${kevBadge}
                    </span>
                </div>
                <div class="property">
                    <span class="key">CVSS Score:</span>
                    <span class="value">${data.cvss_score || 'N/A'}</span>
                </div>
                <div class="property">
                    <span class="key">EPSS Score:</span>
                    <span class="value">${data.epss_score ? (data.epss_score * 100).toFixed(1) + '%' : 'N/A'}</span>
                </div>
                <div class="property">
                    <span class="key">Risk Level:</span>
                    <span class="value">${data.risk_level || 'Unknown'}</span>
                </div>
                <div class="property">
                    <span class="key">Available PoCs:</span>
                    <span class="value">${data.exploit_count || 0}</span>
                </div>
                ${data.description ? `
                <h4>Description</h4>
                <p>${data.description}</p>
                ` : ''}
                ${exploitsSection}
            `;
        }

        content.innerHTML = html;
        drawer.classList.add('open');
    }

    closeInspector() {
        document.getElementById('inspector-drawer').classList.remove('open');
        this.cy.nodes().unselect();
    }

    showError(message) {
        console.error('Dashboard error:', message);
        const loading = document.getElementById('graph-loading');
        if (loading) {
            loading.innerHTML = `
                <div style="color: #ff4757; text-align: center;">
                    <h3>⚠️ Error</h3>
                    <p>${message}</p>
                    <p style="font-size: 0.9em; color: #aaa;">Check browser console for details</p>
                </div>
            `;
            loading.style.display = 'flex';
        }
    }

    updateLayoutSelector() {
        const layoutSelect = document.getElementById('layout-select');
        if (layoutSelect) {
            const availableLayout = this.getAvailableLayout();
            layoutSelect.value = availableLayout;
            
            // Disable cose-bilkent option if not available
            if (typeof cytoscapeCoseBilkent === 'undefined') {
                const coseBilkentOption = layoutSelect.querySelector('option[value="cose-bilkent"]');
                if (coseBilkentOption) {
                    coseBilkentOption.disabled = true;
                    coseBilkentOption.textContent += ' (Not Available)';
                }
            }
        }
    }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    console.log('DOM loaded, initializing dashboard...');
    
    // Check if required libraries are loaded
    if (typeof cytoscape === 'undefined') {
        console.error('Cytoscape.js not loaded');
        return;
    }
    
    // Wait a bit for API client to be ready
    setTimeout(() => {
        window.dashboard = new EASMDashboard();
        window.dashboard.init();
    }, 100);
});
