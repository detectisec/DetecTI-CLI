import re

with open('/home/ls4ss/dev/DetecTI-CLI/web/static/js/graph.js', 'r') as f:
    content = f.read()

# Fix vulnMatchesActiveFilter in applyLeadFilter
def replacement_active(match):
    return """const vulnMatchesActiveFilter = (vulnNode, parentContext = null) => {
            if (!vulnNode) return false;
            const data = typeof vulnNode.data === 'function' ? vulnNode.data() : vulnNode;
            const severity = String(data.severity || '').toUpperCase();
            const source = String(data.source || '').toLowerCase();
            
            if (this.filters.matrix3d) {
                // Dimensão 1: Exposição e Validação Ativa (O Ativo)
                let hasDirectActiveService = false;
                
                if (parentContext && ['service', 'http', 'https'].includes(parentContext.data('type'))) {
                    const sData = parentContext.data();
                    if (sData.verified_active === true || sData.is_active_scan === true) {
                        hasDirectActiveService = true;
                    } else {
                        const sSources = Array.isArray(sData.sources) ? sData.sources : (sData.sources ? [sData.sources] : []);
                        hasDirectActiveService = sSources.some(s => typeof s === 'string' && (s.toLowerCase().includes('masscan') || s.toLowerCase().includes('active')));
                    }
                } else if (typeof vulnNode.incomers === 'function') {
                    const parentServices = vulnNode.incomers('node[type="service"], node[type="http"], node[type="https"]');
                    if (parentServices.length > 0) {
                        hasDirectActiveService = parentServices.some(srv => {
                            const sData = srv.data();
                            if (sData.verified_active === true || sData.is_active_scan === true) return true;
                            const sSources = Array.isArray(sData.sources) ? sData.sources : (sData.sources ? [sData.sources] : []);
                            return sSources.some(s => typeof s === 'string' && (s.toLowerCase().includes('masscan') || s.toLowerCase().includes('active')));
                        });
                    }
                } else if (data.service_id && this.cy) {
                    const srv = this.cy.getElementById(data.service_id);
                    if (srv.length > 0) {
                        const sData = srv.data();
                        hasDirectActiveService = sData.verified_active === true || sData.is_active_scan === true;
                    }
                }

                // Sem serviço ativo diretamente associado -> desqualificado
                if (!hasDirectActiveService) return false;"""

content = re.sub(r'const vulnMatchesActiveFilter = \(vulnNode\) => \{.*?\/\/ Sem serviço ativo diretamente associado -> desqualificado\s*if \(\!hasDirectActiveService\) return false;', replacement_active, content, flags=re.DOTALL)

# Update applyLeadFilter callers
content = content.replace('childVulns.some(vulnMatchesActiveFilter)', 'childVulns.some(v => vulnMatchesActiveFilter(v, srv))')
content = content.replace('directVulnOutgoers.filter(vulnMatchesActiveFilter)', 'directVulnOutgoers.filter(v => vulnMatchesActiveFilter(v, ipNode))')
content = content.replace('vulnOutgoers.filter(vulnMatchesActiveFilter)', 'vulnOutgoers.filter(v => vulnMatchesActiveFilter(v, srvNode))')

# Fix vulnMatchesFilter in applyFilters
def replacement_filter(match):
    return """const vulnMatchesFilter = (vulnNode, parentContext = null) => {
            if (!vulnNode) return false;
            const data = typeof vulnNode.data === 'function' ? vulnNode.data() : vulnNode;
            const severity = String(data.severity || '').toUpperCase();
            const source = String(data.source || '').toLowerCase();

            if (this.filters.matrix3d) {
                // Dimensão 1: Exposição e Validação Ativa (O Ativo)
                let hasDirectActiveService = false;
                
                if (parentContext && ['service', 'http', 'https'].includes(parentContext.data('type'))) {
                    const sData = parentContext.data();
                    if (sData.verified_active === true || sData.is_active_scan === true) {
                        hasDirectActiveService = true;
                    } else {
                        const sSources = Array.isArray(sData.sources) ? sData.sources : (sData.sources ? [sData.sources] : []);
                        hasDirectActiveService = sSources.some(s => typeof s === 'string' && (s.toLowerCase().includes('masscan') || s.toLowerCase().includes('active')));
                    }
                } else if (typeof vulnNode.incomers === 'function') {
                    const parentServices = vulnNode.incomers('node[type="service"], node[type="http"], node[type="https"]');
                    if (parentServices.length > 0) {
                        hasDirectActiveService = parentServices.some(srv => {
                            const sData = srv.data();
                            if (sData.verified_active === true || sData.is_active_scan === true) return true;
                            const sSources = Array.isArray(sData.sources) ? sData.sources : (sData.sources ? [sData.sources] : []);
                            return sSources.some(s => typeof s === 'string' && (s.toLowerCase().includes('masscan') || s.toLowerCase().includes('active')));
                        });
                    }
                } else if (data.service_id && this.cy) {
                    const srv = this.cy.getElementById(data.service_id);
                    if (srv.length > 0) {
                        const sData = srv.data();
                        hasDirectActiveService = sData.verified_active === true || sData.is_active_scan === true;
                    }
                }

                // Sem serviço ativo diretamente associado -> desqualificado
                if (!hasDirectActiveService) return false;"""

content = re.sub(r'const vulnMatchesFilter = \(vulnNode\) => \{.*?\/\/ Sem serviço ativo diretamente associado -> desqualificado\s*if \(\!hasDirectActiveService\) return false;', replacement_filter, content, flags=re.DOTALL)

# Fix applyFilters evaluation loops
eval_nodes_to_keep = """            // Find all matching vulnerabilities within lead scope
            this.cy.nodes('[type="vulnerability"]').forEach(node => {
                if (this.visibleLeadNodes && !this.visibleLeadNodes.has(node.id())) return;
                
                let matchesAnyContext = false;
                node.incomers('node').forEach(parent => {
                    if (vulnMatchesFilter(node, parent)) {
                        matchesAnyContext = true;
                        nodesToKeep.add(parent.id());
                        addAllAncestors(parent, nodesToKeep);
                    }
                });
                
                if (matchesAnyContext) {
                    nodesToKeep.add(node.id());
                } else if (vulnMatchesFilter(node)) {
                    // Fallback for isolated nodes
                    nodesToKeep.add(node.id());
                    addAllAncestors(node, nodesToKeep);
                }
            });"""

content = re.sub(r'\/\/\s*Find all matching vulnerabilities within lead scope\s*this\.cy\.nodes\(\'\[type="vulnerability"\]\'\)\.forEach\(node => \{\s*if \(this\.visibleLeadNodes && !this\.visibleLeadNodes\.has\(node\.id\(\)\)\) return;\s*if \(vulnMatchesFilter\(node\)\) \{\s*nodesToKeep\.add\(node\.id\(\)\);\s*addAllAncestors\(node, nodesToKeep\);\s*\}\s*\}\);', eval_nodes_to_keep, content)

content = content.replace('childVulns.filter(vulnMatchesFilter)', 'childVulns.filter(v => vulnMatchesFilter(v, parentNode))')
content = content.replace('matchingSrvs.length > 0', 'matchingSrvs.length > 0') # unchanged but next line needs fix
content = content.replace('srvNodes.filter(srv => srv.outgoers(\'node[type="vulnerability"]\').some(vulnMatchesFilter))', 'srvNodes.filter(srv => srv.outgoers(\'node[type="vulnerability"]\').some(v => vulnMatchesFilter(v, srv)))')
content = content.replace('directVulns.some(vulnMatchesFilter)', 'directVulns.some(v => vulnMatchesFilter(v, parentNode))')

with open('/home/ls4ss/dev/DetecTI-CLI/web/static/js/graph.js', 'w') as f:
    f.write(content)
