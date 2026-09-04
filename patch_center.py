import re

file_path = "/home/ls4ss/dev/DetecTI-CLI/web/static/js/graph.js"
with open(file_path, "r") as f:
    content = f.read()

pattern = r"""                const childIps = parentFqdn\.outgoers\('edge\[label="RESOLVES_TO"\], edge\[label="MATCHES_DOMAIN"\], edge\[label="ASSOCIATED_DOMAIN"\], edge\[label="CONTAINS_IP"\]'\)\.targets\(\);
                let totalHeight = 0;
                childIps\.forEach\(ip => \{
                    const sCount = srvsByIp\.get\(ip\.id\(\)\) \? srvsByIp\.get\(ip\.id\(\)\)\.length : 0;
                    const sr = Math\.min\(Math\.max\(1, sCount\), 3\);
                    totalHeight \+= Math\.max\(70, sr \* 60\);
                \}\);
                
                // Shift up by half of the total height minus the height of one item \(to center the block\)
                const srvCount = srvsByIp\.get\(node\.id\(\)\) \? srvsByIp\.get\(node\.id\(\)\)\.length : 0;
                const sRows = Math\.min\(Math\.max\(1, srvCount\), 3\);
                const currentHeight = Math\.max\(200, sRows \* 180\);
                
                positions\[node\.id\(\)\]\.y -= \(totalHeight - currentHeight\) / 2;"""

new_logic = """                // New centering approach: Find the actual min and max Y of all siblings placed so far
                const childIps = parentFqdn.outgoers('edge[label="RESOLVES_TO"], edge[label="MATCHES_DOMAIN"], edge[label="ASSOCIATED_DOMAIN"], edge[label="CONTAINS_IP"]').targets();
                let minY = Infinity;
                let maxY = -Infinity;
                
                childIps.forEach(ip => {
                    if (positions[ip.id()]) {
                        minY = Math.min(minY, positions[ip.id()].y);
                        maxY = Math.max(maxY, positions[ip.id()].y);
                    }
                });
                
                if (minY !== Infinity && maxY !== -Infinity) {
                    const blockCenterY = (minY + maxY) / 2;
                    const parentY = positions[pid].y;
                    const shiftY = blockCenterY - parentY;
                    
                    // We only want to calculate the shift ONCE per parent, but we are inside a loop over nodes.
                    // Instead of shifting node.y based on a global totalHeight, we shift it by the offset calculated from its original Y
                    // Actually, if we just shift EVERY node up by (maxY - minY)/2 from its CURRENT Y... wait, no.
                    // The easiest way is to shift node.y by the difference between the block center and the parent Y.
                    positions[node.id()].y -= shiftY;
                }"""

if re.search(pattern, content):
    new_content = re.sub(pattern, new_logic, content)
    with open(file_path, "w") as f:
        f.write(new_content)
    print("Patched centering logic successfully")
else:
    print("Could not find the centering block")
