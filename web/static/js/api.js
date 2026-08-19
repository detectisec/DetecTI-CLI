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

    async getAssets() {
        return this.request('/assets');
    }
}

// Global API client instance
window.api = new APIClient();
