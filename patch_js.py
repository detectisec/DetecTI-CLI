import re

def patch_graph_js():
    path = "web/static/js/graph.js"
    with open(path, "r") as f:
        content = f.read()

    # We need to replace the logic where leadNodes is extracted and evaluated in populateLeadSelector
    
    old_code = r'''            // Extract leads from graph nodes (IP, domain, subdomain)
            let leadNodes = elements.nodes.filter(node => {
                const nodeData = node.data || node;
                const nodeType = nodeData.type;
                return \['ip', 'domain', 'subdomain'\].includes(nodeType);
            });
            
            // IMMEDIATE FALLBACK: If no standard leads, create from ALL nodes
            if (leadNodes.length === 0) {
                leadNodes = elements.nodes.slice();
            }
            
            if (leadNodes.length === 0) {
                leadList.innerHTML = `
                    <div class="lead-loading" style="color: #ff4757;">
                        No lead nodes found in database.<br>
                        <button onclick="location.reload()" style="margin-top: 10px; padding: 5px 10px; background: #007bff; color: white; border: none; border-radius: 3px; cursor: pointer;">Reload Page</button>
                    </div>
                `;
                return;
            }
            
            // Process each lead node
            leadNodes.forEach\((node, index) => \{
                try \{
                    const nodeData = node.data || node;
                    
                    // Find connected vulnerabilities and services to determine 3D Risk level
                    const connectedVulns = this.findConnectedVulnerabilities(nodeData.id, elements);
                    const connectedServices = this.findConnectedServices(nodeData.id, elements);
                    
                    // Threat indicators according to 3D Risk Matrix
                    const vulnCount = connectedVulns.length;
                    const kevVulns = connectedVulns.filter\(v => v.is_cisa_kev === true || v.is_cisa_kev === 'true' || v.is_cisa_kev === 1\);
                    const kevCount = kevVulns.length;
                    const hasKev = kevCount > 0;
                    
                    const criticalVulns = connectedVulns.filter\(v => String\(v.severity || ''\).toUpperCase\(\) === 'CRITICAL'\);
                    const criticalCount = criticalVulns.length;
                    const hasCritical = criticalCount > 0;

                    const highVulns = connectedVulns.filter\(v => String\(v.severity || ''\).toUpperCase\(\) === 'HIGH'\);
                    const highCount = highVulns.length;

                    // PoC weaponization count
                    const pocCount = connectedVulns.reduce\(\(sum, v\) => \{
                        const cnt = \(v.exploits && v.exploits.length\) || v.exploit_count || 0;
                        return sum \+ \(cnt > 0 \? cnt : 0\);
                    \}, 0\);

                    // EPSS metrics
                    let maxEpss = 0.0;
                    let highEpssCount = 0;
                    connectedVulns.forEach\(v => \{
                        const epss = parseFloat\(v.epss_score\) || 0.0;
                        if \(epss > maxEpss\) maxEpss = epss;
                        if \(epss >= 0.20\) highEpssCount\+\+;
                    \}\);

                    // Dimension 1: Active Services & Verified Active Services
                    const serviceCount = connectedServices.length;
                    const verifiedServiceCount = connectedServices.filter\(s => 
                        s.verified_active === true || s.verified === true || s.status === 'active' || s.verified_active === 1
                    \).length;

                    // 3D Composite Risk Score
                    // Dim 3: CISA KEV \(1M each\), PoCs \(200k each\), High EPSS >=20% \(100k each \+ maxEpss\*50k\)
                    // Dim 2: Critical \(50k each\), High \(20k each\), Total Vulns \(1k each\)
                    // Dim 1: Verified Active \(5k each\), Total Services \(100 each\)
                    const threeDScore = \(kevCount \* 1000000\) \+
                                        \(pocCount \* 200000\) \+
                                        \(highEpssCount \* 100000\) \+
                                        \(maxEpss \* 50000\) \+
                                        \(criticalCount \* 50000\) \+
                                        \(highCount \* 20000\) \+
                                        \(verifiedServiceCount \* 5000\) \+
                                        \(vulnCount \* 1000\) \+
                                        \(serviceCount \* 100\);
                    
                    // Create lead object with clean display name handling
                    let displayName = nodeData.label || nodeData.name || nodeData.ip || nodeData.id;
                    
                    // Clean up display name for IPs
                    if \(nodeData.type === 'ip' && nodeData.ip\) \{
                        displayName = nodeData.ip;
                    \}
                    
                    this.leads.push\(\{
                        id: nodeData.id,
                        label: nodeData.label || nodeData.id,
                        display_name: displayName,
                        type: nodeData.type || 'unknown',
                        vuln_count: vulnCount,
                        service_count: serviceCount,
                        verified_service_count: verifiedServiceCount,
                        kev_count: kevCount,
                        has_kev: hasKev,
                        critical_count: criticalCount,
                        has_critical: hasCritical,
                        high_count: highCount,
                        poc_count: pocCount,
                        max_epss: maxEpss,
                        high_epss_count: highEpssCount,
                        three_d_score: threeDScore,
                        is_target: nodeData.is_target === true,
                        // Maintain reference to original node for filtering
                        node: nodeData
                    \}\);
                \} catch \(err\) \{
                    console.error\('Error processing lead node:', node, err\);
                \}
            \}\);'''
            
    new_code = '''            // 1. Look for pre-calculated explore_leads data from the backend
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
                // Extract leads from graph nodes (IP, domain, subdomain)
                let leadNodes = elements.nodes.filter(node => {
                    const nodeData = node.data || node;
                    const nodeType = nodeData.type;
                    return ['ip', 'domain', 'subdomain'].includes(nodeType);
                });
                
                if (leadNodes.length === 0) {
                    leadNodes = elements.nodes.slice();
                }
                
                if (leadNodes.length === 0) {
                    leadList.innerHTML = `
                        <div class="lead-loading" style="color: #ff4757;">
                            No lead nodes found in database.<br>
                            <button onclick="location.reload()" style="margin-top: 10px; padding: 5px 10px; background: #007bff; color: white; border: none; border-radius: 3px; cursor: pointer;">Reload Page</button>
                        </div>
                    `;
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
            }'''
            
    content = re.sub(old_code, new_code, content)
    with open(path, "w") as f:
        f.write(content)

patch_graph_js()
