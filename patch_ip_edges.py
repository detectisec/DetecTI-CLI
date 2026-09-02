import re

with open("web/api/graph_builder.py", "r") as f:
    content = f.read()

# Currently it connects FQDN to ALL IPs it resolves to:
#         for dom_id, ip_ids in domain_to_ips.items():
#             dom_node_id = f"dom_{dom_id}"
#             if dom_node_id in fqdn_set:
#                 for ip_id in ip_ids:
#                     edges.append({"data": {"id": f"e_dom_ip_{dom_id}_{ip_id}", "source": dom_node_id, "target": f"ip_{ip_id}", "label": "RESOLVES_TO"}})

# We should only add the RESOLVES_TO edge if the IP is an explicit target, OR if the FQDN itself is an explicit target!
# If the FQDN is not an explicit target, it only spawned to support the targeted IP. So we shouldn't spam the graph with all its other IPs!

# But wait, what if the scan was a passive scan on the domain? In that case, we want to show all IPs?
# If the scan was on the domain, the domain is an explicit target!
