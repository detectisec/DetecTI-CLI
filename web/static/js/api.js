/**
 * API client for DetecTI-CLI EASM Dashboard
 */

class APIClient {
    constructor(baseURL = '/api/v1') {
        this.baseURL = baseURL;
    }

    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        
        try {
            console.log(`Making API request to: ${url}`);
            
            const response = await fetch(url, {
                headers: {
                    'Accept': 'application/json',
                    ...options.headers
                },
                ...options
            });

            console.log(`API response status: ${response.status}`);

            if (!response.ok) {
                const errorText = await response.text();
                console.error(`API error response: ${errorText}`);
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            const data = await response.json();
            console.log(`API response data:`, data);
            return data;
        } catch (error) {
            console.error(`API request failed: ${endpoint}`, error);
            throw error;
        }
    }

    async getSummary() {
        return this.request('/summary');
    }

    async getGraphData() {
        return this.request('/graph');
    }

    // Removed getLeads() - Lead Selector is now 100% frontend-based using graph data

    async getAssets() {
        return this.request('/assets');
    }

    async getDatabases() {
        return this.request('/databases');
    }

    async selectDatabase(dbName) {
        return this.request('/databases/select', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ name: dbName })
        });
    }

    getExportUrl(format = 'json') {
        return `${this.baseURL}/export?format=${format}`;
    }

    // Target Management & Active Scan APIs
    async getTargets() {
        return this.request('/targets');
    }

    async setTarget(ip) {
        return this.request('/targets/set', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ip: ip })
        });
    }

    async removeTarget(ip) {
        return this.request('/targets/remove', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ip: ip })
        });
    }

    async clearTargets() {
        return this.request('/targets/clear', {
            method: 'POST'
        });
    }

    async checkScanPermissions() {
        return this.request('/scan/check-permissions');
    }

    async startActiveScan(config = {}) {
        return this.request('/scan/active', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(config)
        });
    }

    async startNucleiScan(config = {}) {
        return this.request('/scan/nuclei', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(config)
        });
    }

    async cancelActiveScan(target = null, all = false, scanType = 'all') {
        return this.request('/scan/cancel', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ target: target, all: all, scan_type: scanType })
        });
    }

    async unverifyServices(serviceIds = [], ipAddresses = []) {
        return this.request('/services/unverify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                service_ids: serviceIds,
                ip_addresses: ipAddresses
            })
        });
    }

    async getScanStatus() {
        return this.request('/scan/status');
    }
}

// Global API client instance
window.api = new APIClient();


