import re

with open("web/static/js/graph.js", "r") as f:
    content = f.read()

# 1. Make cose-bilkent the default layout
content = content.replace("return 'breadthfirst';", "return 'cose-bilkent';")

# 2. Add cose-bilkent options
target = """            case 'breadthfirst':
            case 'hierarchical':
                const computedPositions = this.computeSemanticHierarchicalPositions(targetElements);
                return {
                    ...baseOptions,
                    name: 'preset',
                    positions: computedPositions,
                    fit: true,
                    padding: 50
                };"""

replacement = """            case 'breadthfirst':
            case 'hierarchical':
                return {
                    ...baseOptions,
                    name: 'breadthfirst',
                    directed: true,
                    spacingFactor: 1.25,
                    padding: 40,
                    roots: '#target_root'
                };
            case 'cose-bilkent':
                return {
                    ...baseOptions,
                    name: 'cose-bilkent',
                    nodeRepulsion: 45000,
                    idealEdgeLength: 60,
                    edgeElasticity: 0.45,
                    nestingFactor: 0.1,
                    gravity: 0.2,
                    numIter: 2500,
                    tile: true,
                    tilingPaddingVertical: 10,
                    tilingPaddingHorizontal: 10,
                    gravityRangeCompound: 1.5,
                    gravityCompound: 1.0,
                    gravityRange: 3.8
                };"""

content = content.replace(target, replacement)

with open("web/static/js/graph.js", "w") as f:
    f.write(content)
