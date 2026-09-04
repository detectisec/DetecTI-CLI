path = "web/static/js/graph.js"
with open(path, "r") as f:
    content = f.read()

old_1 = """    isTargetMarked(ip) {
        if (!ip) return false;
        const clean = String(ip).replace(/^(ip_|dom_|sub_|target_)/, '').trim();
        return this.markedTargets.has(clean) || this.markedTargets.has(String(ip).trim());
    }"""
new_1 = """    normalizeTargetId(target) {
        if (!target) return target;
        const targetStr = String(target).trim();
        const targetLower = targetStr.toLowerCase();
        
        if (this.leads && Array.isArray(this.leads)) {
            const matchingLead = this.leads.find(l => {
                const lName = (l.name || l.display_name || '').toLowerCase();
                const lId = (l.id || '').toLowerCase();
                return lName === targetLower || lId === targetLower || lId === `dom_${targetLower}` || lId === `sub_${targetLower}` || lId === `ip_${targetLower}`;
            });
            
            if (matchingLead) {
                return matchingLead.id.replace(/^(ip_|dom_|sub_)/, '');
            }
        }
        return targetStr.replace(/^(ip_|dom_|sub_|target_)/, '');
    }

    isTargetMarked(ip) {
        if (!ip) return false;
        const normalizedId = this.normalizeTargetId(ip);
        return this.markedTargets.has(normalizedId) || this.markedTargets.has(String(ip).trim());
    }"""
content = content.replace(old_1, new_1)

old_2 = """    async setTarget(target, node = null) {
        try {
            if (node && (node.data('type') === 'target' || node.id() === 'target_root' || node.data('is_root') === true)) {
                return;
            }
            target = String(target || '').replace(/^(ip_|dom_|sub_|target_)/, '').trim();"""
new_2 = """    async setTarget(target, node = null) {
        try {
            if (node && (node.data('type') === 'target' || node.id() === 'target_root' || node.data('is_root') === true)) {
                return;
            }
            target = this.normalizeTargetId(target);"""
content = content.replace(old_2, new_2)

old_3 = """    async removeTarget(target, node = null) {
        try {
            target = String(target || '').replace(/^(ip_|dom_|sub_|target_)/, '').trim();"""
new_3 = """    async removeTarget(target, node = null) {
        try {
            target = this.normalizeTargetId(target);"""
content = content.replace(old_3, new_3)

old_4 = """    async setTargetsBulk(targets, nodes = null) {
        if (!Array.isArray(targets) || targets.length === 0) return;
        try {
            const cleanTargets = [];
            for (const raw of targets) {
                const clean = String(raw || '').replace(/^(ip_|dom_|sub_|target_)/, '').trim();"""
new_4 = """    async setTargetsBulk(targets, nodes = null) {
        if (!Array.isArray(targets) || targets.length === 0) return;
        try {
            const cleanTargets = [];
            for (const raw of targets) {
                const clean = this.normalizeTargetId(raw);"""
content = content.replace(old_4, new_4)

old_5 = """    async removeTargetsBulk(targets) {
        if (!Array.isArray(targets) || targets.length === 0) return;
        try {
            const cleanTargets = [];
            for (const raw of targets) {
                const clean = String(raw || '').replace(/^(ip_|dom_|sub_|target_)/, '').trim();"""
new_5 = """    async removeTargetsBulk(targets) {
        if (!Array.isArray(targets) || targets.length === 0) return;
        try {
            const cleanTargets = [];
            for (const raw of targets) {
                const clean = this.normalizeTargetId(raw);"""
content = content.replace(old_5, new_5)

with open(path, "w") as f:
    f.write(content)
