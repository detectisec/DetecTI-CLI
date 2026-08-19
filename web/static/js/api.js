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
            const response = await fetch(url, {
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                },
                ...options
            });

            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }

            return await response.json();
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

    async getAssets() {
        return this.request('/assets');
    }
}

// Global API client instance
window.api = new APIClient();
