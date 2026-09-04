def patch_graph_js():
    path = "web/static/js/graph.js"
    with open(path, "r") as f:
        lines = f.readlines()
        
    start_idx = -1
    end_idx = -1
    for i, line in enumerate(lines):
        if "let leadNodes = elements.nodes.filter(node => {" in line:
            start_idx = i - 1 # Include the comment above
        if "Error processing lead node" in line and start_idx != -1:
            end_idx = i + 3
            break
            
    if start_idx == -1 or end_idx == -1:
        print("Could not find boundaries")
        return
        
    new_code = """
            // 1. Look for pre-calculated explore_leads data from the backend
            const rootNode = elements.nodes.find(n => (n.data || n).id === 'target_root');
            const rootData = rootNode ? (rootNode.data || rootNode) : null;
            
            if (rootData && rootData.explore_leads && Array.isArray(rootData.explore_leads)) {
                console.log(`Using pre-calculated explore_leads from backend: ${rootData.explore_leads.length} leads`);
                this.leads = rootData.explore_leads.map(lead => ({
                    id: lead.id,
                    label: lead.label,
                    display_name: lead.display_name || lead.label,
                    type: lead.type,
                    vuln_count: lead.vuln_count || 0,
                    service_count: lead.service_count || 0,
                    verified_service_count: lead.verified_service_count || 0,
                    kev_count: lead.kev_count || 0,
                    has_kev: lead.has_kev || false,
                    critical_count: lead.critical_count || 0,
                    has_critical: (lead.critical_count || 0) > 0,
                    high_count: lead.high_count || 0,
                    poc_count: lead.poc_count || 0,
                    max_epss: lead.max_epss || 0,
                    high_epss_count: lead.high_epss_count || 0,
                    three_d_score: lead.three_d_score || 0,
                    is_target: false // Explicit target state handled separately
                }));
            } else {
                console.warn('explore_leads data not found, falling back to graph traversal...');
                let leadNodes = elements.nodes.filter(node => {
                    const nodeData = node.data || node;
                    const nodeType = nodeData.type;
                    return ['ip', 'domain', 'subdomain'].includes(nodeType);
                });
                if (leadNodes.length === 0) leadNodes = elements.nodes.slice();
                if (leadNodes.length === 0) {
                    leadList.innerHTML = `<div class="lead-loading" style="color: #ff4757;">No lead nodes found in database.</div>`;
                    return;
                }
                
                leadNodes.forEach((node, index) => {
                    try {
                        const nodeData = node.data || node;
                        const connectedVulns = this.findConnectedVulnerabilities(nodeData.id, elements);
                        const connectedServices = this.findConnectedServices(nodeData.id, elements);
                        
                        const vulnCount = connectedVulns.length;
                        const kevVulns = connectedVulns.filter(v => v.is_cisa_kev === true || v.is_cisa_kev === 'true' || v.is_cisa_kev === 1);
                        const kevCount = kevVulns.length;
                        const criticalVulns = connectedVulns.filter(v => String(v.severity || '').toUpperCase() === 'CRITICAL');
                        const criticalCount = criticalVulns.length;
                        const highVulns = connectedVulns.filter(v => String(v.severity || '').toUpperCase() === 'HIGH');
                        const highCount = highVulns.length;
                        const pocCount = connectedVulns.reduce((sum, v) => sum + ((v.exploits && v.exploits.length) || v.exploit_count || 0 > 0 ? ((v.exploits && v.exploits.length) || v.exploit_count || 0) : 0), 0);
                        let maxEpss = 0.0;
                        let highEpssCount = 0;
                        connectedVulns.forEach(v => {
                            const epss = parseFloat(v.epss_score) || 0.0;
                            if (epss > maxEpss) maxEpss = epss;
                            if (epss >= 0.20) highEpssCount++;
                        });
                        const serviceCount = connectedServices.length;
                        const verifiedServiceCount = connectedServices.filter(s => s.verified_active === true || s.verified === true || s.status === 'active' || s.verified_active === 1).length;
                        
                        const threeDScore = (kevCount * 1000000) + (pocCount * 200000) + (highEpssCount * 100000) + (maxEpss * 50000) + (criticalCount * 50000) + (highCount * 20000) + (verifiedServiceCount * 5000) + (vulnCount * 1000) + (serviceCount * 100);
                        let displayName = nodeData.type === 'ip' && nodeData.ip ? nodeData.ip : (nodeData.label || nodeData.name || nodeData.ip || nodeData.id);
                        
                        this.leads.push({
                            id: nodeData.id,
                            label: nodeData.label || nodeData.id,
                            display_name: displayName,
                            type: nodeData.type || 'unknown',
                            vuln_count: vulnCount,
                            service_count: serviceCount,
                            verified_service_count: verifiedServiceCount,
                            kev_count: kevCount,
                            has_kev: kevCount > 0,
                            critical_count: criticalCount,
                            has_critical: criticalCount > 0,
                            high_count: highCount,
                            poc_count: pocCount,
                            max_epss: maxEpss,
                            high_epss_count: highEpssCount,
                            three_d_score: threeDScore,
                            is_target: nodeData.is_target === true,
                            node: nodeData
                        });
                    } catch (err) {
                        console.error('Error processing lead node:', node, err);
                    }
                });
            }
"""
    lines[start_idx:end_idx] = [new_code]
    with open(path, "w") as f:
        f.writelines(lines)

patch_graph_js()
