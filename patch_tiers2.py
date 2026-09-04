import re

file_path = "/home/ls4ss/dev/DetecTI-CLI/web/static/js/graph.js"
with open(file_path, "r") as f:
    content = f.read()

old_tier_logic = """        // 1. Partition nodes into Semantic Topological Tiers
        const tier0_target = [];
        const tier1_direct_targets = [];
        const tier2_resolved_ips = [];
        const tier3_service = [];
        const tier4_vuln = [];

        nodes.forEach(node => {
            const data = node.data();
            const type = data.type;

            if (type === 'target' || data.id === 'target_root' || data.is_root === true) {
                tier0_target.push(node);
            } else if (['service', 'http', 'https', 'cluster_services'].includes(type)) {
                tier3_service.push(node);
            } else if (['vulnerability', 'cluster_vulns'].includes(type)) {
                tier4_vuln.push(node);
            } else if (['domain', 'subdomain'].includes(type)) {
                // All FQDNs go to Tier 1 Layout
                tier1_direct_targets.push(node);
            } else if (type === 'ip' || type === 'network') {
                // All IPs go to Tier 2 Layout
                tier2_resolved_ips.push(node);
            } else {
                // Fallback
                tier2_resolved_ips.push(node);
            }
        });"""

new_tier_logic = """        // 1. Partition nodes into Semantic Topological Tiers
        const tier0_target = [];
        const tier1_domains = [];
        const tier2_subdomains = [];
        const tier3_ips = [];
        const tier4_service = [];
        const tier5_vuln = [];

        nodes.forEach(node => {
            const data = node.data();
            const type = data.type;

            if (type === 'target' || data.id === 'target_root' || data.is_root === true) {
                tier0_target.push(node);
            } else if (type === 'domain') {
                tier1_domains.push(node);
            } else if (type === 'subdomain') {
                tier2_subdomains.push(node);
            } else if (type === 'ip' || type === 'network') {
                tier3_ips.push(node);
            } else if (['service', 'http', 'https', 'cluster_services'].includes(type)) {
                tier4_service.push(node);
            } else if (['vulnerability', 'cluster_vulns'].includes(type)) {
                tier5_vuln.push(node);
            } else {
                tier3_ips.push(node);
            }
        });

        // Create legacy aliases so the rest of the existing coordinate code still works,
        // but we ensure they are strictly processed in the new order.
        const tier1_direct_targets = tier1_domains;
        const tier2_resolved_ips = [...tier2_subdomains, ...tier3_ips]; // Wait, I should rewrite the layout block instead to be clean.
"""

# Let's replace the ENTIRE layout logic to be perfectly hierarchical!
