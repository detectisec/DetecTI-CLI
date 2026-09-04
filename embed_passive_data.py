import re

path = "web/api/graph_builder.py"
with open(path, "r") as f:
    content = f.read()

old = r'''        # Filter edges to only keep those where both source and target are spawned
        spawned_node_ids = \{n\["data"\]\["id"\] for n in nodes\}'''

new = '''        # --- EMBED PASSIVE DATA FOR FQDN INSPECTOR ---
        # To support the inspector showing data without spawning the nodes visually:
        # Build lookups for all passive data
        ip_data_map = {n["data"]["id"]: n["data"] for n in ip_nodes}
        srv_data_map = {n["data"]["id"]: n["data"] for n in service_nodes}
        vuln_data_map = {n["data"]["id"]: n["data"] for n in vuln_nodes}
        
        # Build relationship mappings (all edges, even if not spawned)
        ip_to_srvs = {}
        for e in service_edges:
            src = e["data"]["source"]
            tgt = e["data"]["target"]
            if src not in ip_to_srvs: ip_to_srvs[src] = []
            ip_to_srvs[src].append(tgt)
            
        srv_or_ip_to_vulns = {}
        for e in vuln_edges:
            src = e["data"]["source"]
            tgt = e["data"]["target"]
            if src not in srv_or_ip_to_vulns: srv_or_ip_to_vulns[src] = []
            srv_or_ip_to_vulns[src].append(tgt)
            
        # For each spawned FQDN node, embed its unspawned passive data
        for n in nodes:
            if n["data"]["type"] in ("domain", "subdomain"):
                nid = n["data"]["id"]
                n_ips = []
                n_srvs = []
                n_vulns = []
                
                # Get IPs for this FQDN
                ip_ids = set()
                if n["data"]["type"] == "domain":
                    dom_id = nid.replace("dom_", "")
                    ip_ids = domain_to_ips.get(int(dom_id) if dom_id.isdigit() else dom_id, set())
                else:
                    sub_id = nid.replace("sub_", "")
                    ip_ids = subdomain_to_ips.get(int(sub_id) if sub_id.isdigit() else sub_id, set())
                    
                for ip_id in ip_ids:
                    ip_node_id = f"ip_{ip_id}"
                    if ip_node_id in ip_data_map:
                        n_ips.append(ip_data_map[ip_node_id])
                    
                    for srv_id in ip_to_srvs.get(ip_node_id, []):
                        if srv_id in srv_data_map:
                            n_srvs.append(srv_data_map[srv_id])
                        for vuln_id in srv_or_ip_to_vulns.get(srv_id, []):
                            if vuln_id in vuln_data_map:
                                n_vulns.append(vuln_data_map[vuln_id])
                                
                    for vuln_id in srv_or_ip_to_vulns.get(ip_node_id, []):
                        if vuln_id in vuln_data_map:
                            n_vulns.append(vuln_data_map[vuln_id])
                            
                n["data"]["passive_ips"] = n_ips
                n["data"]["passive_services"] = n_srvs
                n["data"]["passive_vulns"] = n_vulns

        # Filter edges to only keep those where both source and target are spawned
        spawned_node_ids = {n["data"]["id"] for n in nodes}'''

content = re.sub(old, new, content)

with open(path, "w") as f:
    f.write(content)
