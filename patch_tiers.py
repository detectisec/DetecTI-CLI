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
            } else {
                // Determine if node is a direct target connected to target_root via CONTAINS_TARGET
                const hasContainsTarget = node.incomers('edge[label="CONTAINS_TARGET"]').some(e => {
                    const src = e.source();
                    return src.id() === 'target_root' || src.data('is_root') === true;
                });

                if (hasContainsTarget) {
                    tier1_direct_targets.push(node);
                } else {
                    // Passive IPs, domains, subdomains, networks go to Tier 2 (Resolved/Passive Infrastructure)
                    tier2_resolved_ips.push(node);
                }
            }
        });"""

new_tier_logic = """        // 1. Partition nodes into Semantic Topological Tiers
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

if old_tier_logic in content:
    with open(file_path, "w") as f:
        f.write(content.replace(old_tier_logic, new_tier_logic))
    print("Patched tiers successfully")
else:
    print("Could not find the old tier logic block")
