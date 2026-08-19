/**
 * DetecTI-CLI EASM Dashboard - Cytoscape.js Graph Implementation
 */

class EASMDashboard {
    constructor() {
        this.cy = null;
        this.graphData = null;
        this.filters = {
            kev: false,
            highEpss: false,
            critical: false,
            https: false
        };
        
        // Don't auto-initialize, wait for DOM
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
            
            // Initialize Cytoscape
            console.log('Initializing Cytoscape...');
            this.initCytoscape();
            
            // Load and render graph
            console.log('Loading graph data...');
            await this.loadGraph();
            
            // Setup event listeners
            console.log('Setting up event listeners...');
            this.setupEventListeners();
            
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

    initCytoscape() {
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
                        'label': 'data(label)',
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
                
                // Critical vulnerabilities (pulsing animation)
                {
                    selector: 'node[risk_level="critical"]',
                    style: {
                        'background-color': '#ff3838',
                        'border-color': '#ff1744',
                        'border-width': '3px'
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
                
                // Vulnerability edges (red)
                {
                    selector: 'edge[label="HAS_VULN"]',
                    style: {
                        'line-color': '#e74c3c',
                        'target-arrow-color': '#e74c3c',
                        'width': '3px'
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
                name: 'cose-bilkent',
                animate: true,
                animationDuration: 1000,
                fit: true,
                padding: 50,
                nodeRepulsion: 8000,
                idealEdgeLength: 100,
                edgeElasticity: 0.1,
                nestingFactor: 0.1,
                gravity: 0.1,
                numIter: 2500,
                tile: true,
                tilingPaddingVertical: 10,
                tilingPaddingHorizontal: 10
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
                this.applyFilters();
                
                // Run layout
                const layout = this.cy.layout({ 
                    name: 'cose-bilkent', 
                    animate: true,
                    animationDuration: 1000,
                    fit: true,
                    padding: 50
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

        document.getElementById('filter-https').addEventListener('change', (e) => {
            this.filters.https = e.target.checked;
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
            this.cy.layout({ name: layoutName, animate: true }).run();
        });

        // Layout selector
        document.getElementById('layout-select').addEventListener('change', (e) => {
            this.cy.layout({ name: e.target.value, animate: true }).run();
        });

        // Inspector close button
        document.getElementById('close-inspector').addEventListener('click', () => {
            this.closeInspector();
        });
    }

    applyFilters() {
        if (!this.cy) return;

        // Show all nodes first
        this.cy.nodes().show();
        this.cy.edges().show();

        // Apply vulnerability filters - when any filter is active, hide non-matching vulnerabilities
        const hasVulnFilters = this.filters.kev || this.filters.highEpss || this.filters.critical;
        
        if (hasVulnFilters) {
            this.cy.nodes('[type="vulnerability"]').forEach(node => {
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
                
                if (!shouldShow) {
                    node.hide();
                }
            });
        }

        // Apply HTTPS service filter
        if (this.filters.https) {
            // Hide non-HTTPS services
            this.cy.nodes('[type="service"], [type="http"]').forEach(node => {
                if (node.data('type') !== 'https' && node.data('ssl') !== true) {
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
            const kevBadge = data.is_cisa_kev === 'true' ? '<span class="vulnerability-badge kev">CISA KEV</span>' : '';
            const severityClass = (data.severity || 'unknown').toLowerCase();
            
            html = `
                <h4>Vulnerability Details</h4>
                <div class="property">
                    <span class="key">CVE ID:</span>
                    <span class="value">${data.cve_id}</span>
                </div>
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
                ${data.description ? `
                <h4>Description</h4>
                <p>${data.description}</p>
                ` : ''}
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
