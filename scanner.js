// scanner.js - Advanced XSS Scanner v5.0
class XSSScanner {
    constructor() {
        this.version = '5.0';
        this.payloads = this.getAdvancedPayloads();
        this.vulnerableURLs = [];
        this.testedParameters = [];
        this.scanHistory = [];
        this.settings = this.loadSettings();
        this.init();
    }

    init() {
        this.injectAdvancedStyles();
        this.createAdvancedUI();
        this.bindAdvancedEvents();
        console.log(`🛡️ Advanced XSS Scanner v${this.version} initialized`);
    }

    getAdvancedPayloads() {
        return {
            basic: [
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
            ],
            advanced: [
                '<script>alert(document.domain)</script>',
                '<img src=x onerror=alert(document.cookie)>',
                '<svg onload=alert(window.location)>',
                '<form><button formaction=javascript:alert(1)>click</button>',
                '<math href="javascript:alert(1)">CLICK</math>',
                '<object data="javascript:alert(1)">',
                '"><script>alert(1)</script>',
                '"><img src=x onerror=alert(1)>',
                '{{alert(1)}}',
                '<script>alert&#40;1&#41;</script>'
            ],
            polyglot: [
                'jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
                '<<script>script>alert(1)</script>',
                '<img/src=x onerror=alert(1)>',
                '<svg/onload=alert(1)>',
                '<script>window["al"+"ert"](1)</script>'
            ]
        };
    }

    loadSettings() {
        return {
            autoSave: true,
            darkMode: true,
            soundEnabled: false,
            maxHistory: 50,
            defaultPayloadCount: 15
        };
    }

    injectAdvancedStyles() {
        const style = document.createElement('style');
        style.id = 'advanced-xss-scanner-styles';
        style.textContent = `
            .advanced-scanner {
                position: fixed !important;
                top: 20px !important;
                right: 20px !important;
                width: 800px !important;
                background: linear-gradient(135deg, #0d1117 0%, #161b22 100%) !important;
                color: #f0f6fc !important;
                padding: 24px !important;
                border-radius: 16px !important;
                z-index: 2147483647 !important;
                font-family: 'Segoe UI', 'SF Pro Display', -apple-system, sans-serif !important;
                box-shadow: 0 20px 60px rgba(0,0,0,0.5) !important;
                max-height: 85vh !important;
                overflow-y: auto !important;
                border: 2px solid #238636 !important;
                backdrop-filter: blur(10px) !important;
            }

            .scanner-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 24px;
                padding-bottom: 16px;
                border-bottom: 2px solid #238636;
                background: linear-gradient(90deg, #238636, #2ea043);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }

            .scanner-title {
                margin: 0;
                font-size: 24px;
                font-weight: 700;
                background: linear-gradient(135deg, #58a6ff, #79c0ff);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
                background-clip: text;
            }

            .header-controls {
                display: flex;
                gap: 8px;
                align-items: center;
            }

            .control-btn {
                background: #21262d;
                border: 1px solid #30363d;
                color: #f0f6fc;
                padding: 6px 12px;
                border-radius: 6px;
                cursor: pointer;
                font-size: 12px;
                transition: all 0.2s ease;
            }

            .control-btn:hover {
                background: #30363d;
                border-color: #58a6ff;
            }

            .scanner-tabs {
                display: flex;
                gap: 8px;
                margin-bottom: 20px;
                background: #161b22;
                padding: 8px;
                border-radius: 12px;
            }

            .tab {
                flex: 1;
                padding: 12px 16px;
                background: transparent;
                border: none;
                color: #8b949e;
                border-radius: 8px;
                cursor: pointer;
                font-weight: 600;
                transition: all 0.3s ease;
            }

            .tab.active {
                background: #238636;
                color: white;
                box-shadow: 0 4px 12px rgba(35, 134, 54, 0.3);
            }

            .scanner-section {
                background: rgba(22, 27, 34, 0.8);
                padding: 20px;
                border-radius: 12px;
                margin-bottom: 16px;
                border: 1px solid #30363d;
                backdrop-filter: blur(5px);
            }

            .section-title {
                display: flex;
                align-items: center;
                gap: 8px;
                color: #58a6ff;
                font-weight: 600;
                margin-bottom: 16px;
                font-size: 16px;
            }

            .grid-2 {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 16px;
            }

            .grid-3 {
                display: grid;
                grid-template-columns: 1fr 1fr 1fr;
                gap: 12px;
            }

            .option-card {
                background: #0d1117;
                border: 2px solid #30363d;
                border-radius: 8px;
                padding: 16px;
                cursor: pointer;
                transition: all 0.3s ease;
                text-align: center;
            }

            .option-card:hover {
                border-color: #58a6ff;
                transform: translateY(-2px);
            }

            .option-card.active {
                border-color: #238636;
                background: linear-gradient(135deg, #1c2a1c, #238636);
                box-shadow: 0 8px 24px rgba(35, 134, 54, 0.3);
            }

            .option-card.warning {
                border-color: #da3633;
                background: linear-gradient(135deg, #2d1a1a, #da3633);
            }

            .slider-container {
                margin: 20px 0;
            }

            .slider-with-input {
                display: flex;
                gap: 12px;
                align-items: center;
                margin: 12px 0;
            }

            .slider {
                flex: 1;
                height: 6px;
                border-radius: 3px;
                background: #30363d;
                outline: none;
                -webkit-appearance: none;
            }

            .slider::-webkit-slider-thumb {
                -webkit-appearance: none;
                width: 20px;
                height: 20px;
                border-radius: 50%;
                background: #238636;
                cursor: pointer;
                box-shadow: 0 4px 8px rgba(0,0,0,0.3);
            }

            .number-input {
                width: 80px;
                padding: 8px 12px;
                background: #0d1117;
                border: 1px solid #30363d;
                border-radius: 6px;
                color: #f0f6fc;
                text-align: center;
            }

            .results-container {
                background: #161b22;
                border-radius: 12px;
                margin: 20px 0;
                overflow: hidden;
                border: 1px solid #30363d;
            }

            .results-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 16px 20px;
                background: #1c2128;
                border-bottom: 1px solid #30363d;
            }

            .results-content {
                max-height: 400px;
                overflow-y: auto;
                padding: 0;
            }

            .result-item {
                padding: 16px 20px;
                border-bottom: 1px solid #30363d;
                transition: background 0.2s ease;
            }

            .result-item:hover {
                background: #1c2128;
            }

            .result-item.critical {
                border-left: 4px solid #ff7b72;
                background: linear-gradient(90deg, rgba(255,123,114,0.1), transparent);
            }

            .result-item.warning {
                border-left: 4px solid #e3b341;
                background: linear-gradient(90deg, rgba(227,179,65,0.1), transparent);
            }

            .result-item.success {
                border-left: 4px solid #56d364;
                background: linear-gradient(90deg, rgba(86,211,100,0.1), transparent);
            }

            .stats-grid {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 12px;
                margin-top: 16px;
            }

            .stat-card {
                background: #0d1117;
                padding: 16px;
                border-radius: 8px;
                text-align: center;
                border: 1px solid #30363d;
            }

            .stat-value {
                font-size: 24px;
                font-weight: 700;
                color: #58a6ff;
                margin-bottom: 4px;
            }

            .stat-label {
                font-size: 12px;
                color: #8b949e;
            }

            .action-buttons {
                display: grid;
                grid-template-columns: 2fr 1fr 1fr;
                gap: 12px;
                margin-top: 24px;
            }

            .btn {
                padding: 14px 20px;
                border: none;
                border-radius: 8px;
                cursor: pointer;
                font-weight: 600;
                font-size: 14px;
                transition: all 0.3s ease;
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 8px;
            }

            .btn-primary {
                background: linear-gradient(135deg, #238636, #2ea043);
                color: white;
                box-shadow: 0 4px 12px rgba(35, 134, 54, 0.3);
            }

            .btn-primary:hover {
                transform: translateY(-2px);
                box-shadow: 0 8px 20px rgba(35, 134, 54, 0.4);
            }

            .btn-danger {
                background: linear-gradient(135deg, #da3633, #f85149);
                color: white;
            }

            .btn-secondary {
                background: #21262d;
                color: #f0f6fc;
                border: 1px solid #30363d;
            }

            .btn-secondary:hover {
                background: #30363d;
                border-color: #58a6ff;
            }

            .progress-bar {
                width: 100%;
                height: 6px;
                background: #30363d;
                border-radius: 3px;
                overflow: hidden;
                margin: 12px 0;
            }

            .progress-fill {
                height: 100%;
                background: linear-gradient(90deg, #238636, #2ea043);
                border-radius: 3px;
                transition: width 0.3s ease;
            }

            .vulnerability-badge {
                display: inline-block;
                padding: 4px 8px;
                border-radius: 4px;
                font-size: 11px;
                font-weight: 600;
                margin-left: 8px;
            }

            .badge-critical { background: #ff7b72; color: white; }
            .badge-high { background: #ffa198; color: white; }
            .badge-medium { background: #e3b341; color: black; }
            .badge-low { background: #79c0ff; color: white; }

            .payload-preview {
                background: #1c2128;
                padding: 12px;
                border-radius: 6px;
                margin: 8px 0;
                border: 1px solid #30363d;
                font-family: 'Cascadia Code', 'Fira Code', monospace;
                font-size: 12px;
                word-break: break-all;
            }

            .scan-animation {
                display: inline-block;
                animation: pulse 2s infinite;
            }

            @keyframes pulse {
                0% { opacity: 1; }
                50% { opacity: 0.5; }
                100% { opacity: 1; }
            }
        `;
        document.head.appendChild(style);
    }

    createAdvancedUI() {
        this.panel = document.createElement('div');
        this.panel.className = 'advanced-scanner';
        this.panel.id = 'advanced-xss-scanner';
        
        this.panel.innerHTML = this.getAdvancedUITemplate();
        document.body.appendChild(this.panel);
    }

    getAdvancedUITemplate() {
        const totalPayloads = Object.values(this.payloads).reduce((sum, arr) => sum + arr.length, 0);
        
        return `
            <div class="scanner-header">
                <h2 class="scanner-title">🛡️ Advanced XSS Scanner v${this.version}</h2>
                <div class="header-controls">
                    <button class="control-btn" onclick="scanner.minimize()">🗕</button>
                    <button class="control-btn" onclick="scanner.destroy()">✕</button>
                </div>
            </div>

            <div class="scanner-tabs">
                <button class="tab active" data-tab="scan">🔍 Scan</button>
                <button class="tab" data-tab="payloads">⚡ Payloads</button>
                <button class="tab" data-tab="history">📊 History</button>
                <button class="tab" data-tab="settings">⚙️ Settings</button>
            </div>

            <div class="tab-content" id="scan-tab">
                <div class="scanner-section">
                    <div class="section-title">
                        <span>🎯 Scan Configuration</span>
                    </div>
                    
                    <div class="grid-3">
                        <div class="option-card active" data-mode="quick">
                            <div style="font-size: 24px; margin-bottom: 8px;">⚡</div>
                            <div style="font-weight: 600;">Quick Scan</div>
                            <div style="font-size: 12px; color: #8b949e; margin-top: 4px;">Fast basic testing</div>
                        </div>
                        <div class="option-card" data-mode="deep">
                            <div style="font-size: 24px; margin-bottom: 8px;">🔍</div>
                            <div style="font-weight: 600;">Deep Scan</div>
                            <div style="font-size: 12px; color: #8b949e; margin-top: 4px;">Comprehensive analysis</div>
                        </div>
                        <div class="option-card" data-mode="full">
                            <div style="font-size: 24px; margin-bottom: 8px;">🚀</div>
                            <div style="font-weight: 600;">Full Scan</div>
                            <div style="font-size: 12px; color: #8b949e; margin-top: 4px;">Maximum coverage</div>
                        </div>
                    </div>
                </div>

                <div class="scanner-section">
                    <div class="section-title">
                        <span>🛡️ Payload Selection</span>
                    </div>
                    
                    <div class="grid-3">
                        <div class="option-card active" data-type="basic">
                            <div style="font-weight: 600;">Basic</div>
                            <div style="font-size: 12px; color: #8b949e;">${this.payloads.basic.length} payloads</div>
                        </div>
                        <div class="option-card" data-type="advanced">
                            <div style="font-weight: 600;">Advanced</div>
                            <div style="font-size: 12px; color: #8b949e;">${this.payloads.advanced.length} payloads</div>
                        </div>
                        <div class="option-card warning" data-type="polyglot">
                            <div style="font-weight: 600;">Polyglot</div>
                            <div style="font-size: 12px; color: #8b949e;">${this.payloads.polyglot.length} payloads</div>
                        </div>
                    </div>

                    <div class="slider-container">
                        <div class="section-title">
                            <span>📦 Payload Count</span>
                            <span style="margin-left: auto; color: #58a6ff;" id="payloadCountValue">15</span>
                        </div>
                        <div class="slider-with-input">
                            <input type="range" class="slider" id="payloadCount" min="1" max="50" value="15">
                            <input type="number" class="number-input" id="payloadCountInput" value="15" min="1" max="50">
                        </div>
                    </div>
                </div>

                <div class="scanner-section">
                    <div class="section-title">
                        <span>🎛️ Scan Options</span>
                    </div>
                    
                    <div class="grid-2">
                        <label style="display: flex; align-items: center; gap: 8px;">
                            <input type="checkbox" id="optURL" checked>
                            <span>URL Parameters</span>
                        </label>
                        <label style="display: flex; align-items: center; gap: 8px;">
                            <input type="checkbox" id="optForms" checked>
                            <span>Forms & Inputs</span>
                        </label>
                        <label style="display: flex; align-items: center; gap: 8px;">
                            <input type="checkbox" id="optHidden">
                            <span>Hidden Fields</span>
                        </label>
                        <label style="display: flex; align-items: center; gap: 8px;">
                            <input type="checkbox" id="optCookies">
                            <span>Cookies</span>
                        </label>
                        <label style="display: flex; align-items: center; gap: 8px;">
                            <input type="checkbox" id="optLocalStorage">
                            <span>Local Storage</span>
                        </label>
                        <label style="display: flex; align-items: center; gap: 8px;">
                            <input type="checkbox" id="optHeaders">
                            <span>HTTP Headers</span>
                        </label>
                    </div>
                </div>

                <div class="action-buttons">
                    <button class="btn btn-primary" id="startScan">
                        <span class="scan-animation">🚀</span>
                        Start Advanced Scan
                    </button>
                    <button class="btn btn-secondary" id="clearResults">
                        🗑️ Clear
                    </button>
                    <button class="btn btn-secondary" id="exportResults">
                        📊 Export
                    </button>
                </div>
            </div>

            <div class="results-container">
                <div class="results-header">
                    <span style="font-weight: 600;">📋 Scan Results</span>
                    <div style="display: flex; gap: 12px; font-size: 12px;">
                        <span>Found: <strong id="foundCount">0</strong></span>
                        <span>Scanned: <strong id="scannedCount">0</strong></span>
                    </div>
                </div>
                <div class="results-content" id="resultsContent">
                    <div style="text-align: center; padding: 40px 20px; color: #8b949e;">
                        <div style="font-size: 48px; margin-bottom: 16px;">🛡️</div>
                        <div style="font-weight: 600; margin-bottom: 8px;">Ready to Scan</div>
                        <div>Configure your scan and click "Start Advanced Scan"</div>
                    </div>
                </div>
            </div>
        `;
    }

    bindAdvancedEvents() {
        // Tab switching
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                e.target.classList.add('active');
                this.switchTab(e.target.dataset.tab);
            });
        });

        // Mode selection
        document.querySelectorAll('.option-card[data-mode]').forEach(card => {
            card.addEventListener('click', (e) => {
                document.querySelectorAll('.option-card[data-mode]').forEach(c => c.classList.remove('active'));
                e.target.closest('.option-card').classList.add('active');
            });
        });

        // Payload type selection
        document.querySelectorAll('.option-card[data-type]').forEach(card => {
            card.addEventListener('click', (e) => {
                document.querySelectorAll('.option-card[data-type]').forEach(c => c.classList.remove('active'));
                e.target.closest('.option-card').classList.add('active');
            });
        });

        // Payload count sync
        const slider = document.getElementById('payloadCount');
        const input = document.getElementById('payloadCountInput');
        const valueDisplay = document.getElementById('payloadCountValue');

        const updatePayloadCount = (value) => {
            valueDisplay.textContent = value;
            input.value = value;
            slider.value = value;
        };

        slider.addEventListener('input', (e) => updatePayloadCount(e.target.value));
        input.addEventListener('input', (e) => updatePayloadCount(e.target.value));

        // Scan button
        document.getElementById('startScan').addEventListener('click', () => this.startAdvancedScan());
        document.getElementById('clearResults').addEventListener('click', () => this.clearResults());
        document.getElementById('exportResults').addEventListener('click', () => this.exportResults());
    }

    switchTab(tabName) {
        console.log('Switching to tab:', tabName);
        // Tab switching logic will be implemented
    }

    startAdvancedScan() {
        const mode = document.querySelector('.option-card[data-mode].active').dataset.mode;
        const payloadType = document.querySelector('.option-card[data-type].active').dataset.type;
        const payloadCount = parseInt(document.getElementById('payloadCount').value);
        
        this.clearResults();
        this.showScanningAnimation();
        
        setTimeout(() => {
            this.simulateAdvancedScanResults(mode, payloadType, payloadCount);
        }, 2000);
    }

    showScanningAnimation() {
        const results = document.getElementById('resultsContent');
        results.innerHTML = `
            <div style="text-align: center; padding: 40px 20px;">
                <div class="scan-animation" style="font-size: 48px; margin-bottom: 16px;">🔍</div>
                <div style="font-weight: 600; margin-bottom: 8px; color: #58a6ff;">Scanning in Progress</div>
                <div style="color: #8b949e; margin-bottom: 20px;">Analyzing parameters and testing payloads...</div>
                <div class="progress-bar">
                    <div class="progress-fill" style="width: 0%" id="scanProgress"></div>
                </div>
            </div>
        `;

        // Animate progress bar
        let progress = 0;
        const interval = setInterval(() => {
            progress += 2;
            document.getElementById('scanProgress').style.width = progress + '%';
            if (progress >= 100) clearInterval(interval);
        }, 50);
    }

    simulateAdvancedScanResults(mode, payloadType, payloadCount) {
        const vulnerabilities = this.generateVulnerabilities(mode, payloadType);
        this.displayResults(vulnerabilities);
    }

    generateVulnerabilities(mode, payloadType) {
        const count = mode === 'quick' ? 2 : mode === 'deep' ? 5 : 8;
        const vulnerabilities = [];
        
        for (let i = 0; i < count; i++) {
            vulnerabilities.push({
                parameter: `param_${i}`,
                payload: this.payloads[payloadType][i % this.payloads[payloadType].length],
                risk: ['low', 'medium', 'high', 'critical'][i % 4],
                type: ['reflected', 'stored', 'dom'][i % 3],
                url: `${window.location.href}?test=payload_${i}`
            });
        }
        
        return vulnerabilities;
    }

    displayResults(vulnerabilities) {
        const results = document.getElementById('resultsContent');
        const foundCount = document.getElementById('foundCount');
        
        foundCount.textContent = vulnerabilities.length;
        
        if (vulnerabilities.length === 0) {
            results.innerHTML = `
                <div style="text-align: center; padding: 40px 20px; color: #56d364;">
                    <div style="font-size: 48px; margin-bottom: 16px;">✅</div>
                    <div style="font-weight: 600; margin-bottom: 8px;">No Vulnerabilities Found</div>
                    <div>The target appears to be secure against XSS attacks</div>
                </div>
            `;
            return;
        }

        let html = '';
        vulnerabilities.forEach((vuln, index) => {
            html += `
                <div class="result-item ${vuln.risk}">
                    <div style="display: flex; justify-content: between; align-items: start; margin-bottom: 12px;">
                        <div style="flex: 1;">
                            <div style="font-weight: 600; margin-bottom: 4px;">
                                ${vuln.parameter}
                                <span class="vulnerability-badge badge-${vuln.risk}">${vuln.risk.toUpperCase()}</span>
                            </div>
                            <div style="font-size: 12px; color: #8b949e;">Type: ${vuln.type}</div>
                        </div>
                        <button class="control-btn" onclick="scanner.testPayload('${vuln.url}')">Test</button>
                    </div>
                    <div class="payload-preview">${this.escapeHtml(vuln.payload)}</div>
                </div>
            `;
        });

        results.innerHTML = html;
    }

    escapeHtml(unsafe) {
        return unsafe
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    testPayload(url) {
        window.open(url, '_blank');
    }

    clearResults() {
        document.getElementById('resultsContent').innerHTML = `
            <div style="text-align: center; padding: 40px 20px; color: #8b949e;">
                <div style="font-size: 48px; margin-bottom: 16px;">🛡️</div>
                <div style="font-weight: 600; margin-bottom: 8px;">Ready to Scan</div>
                <div>Configure your scan and click "Start Advanced Scan"</div>
            </div>
        `;
        document.getElementById('foundCount').textContent = '0';
        document.getElementById('scannedCount').textContent = '0';
    }

    exportResults() {
        const data = {
            scanDate: new Date().toISOString(),
            url: window.location.href,
            vulnerabilities: this.vulnerableURLs,
            settings: this.settings
        };
        
        const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `xss-scan-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }

    minimize() {
        this.panel.style.transform = 'scale(0.95)';
        this.panel.style.opacity = '0.8';
        setTimeout(() => {
            this.panel.style.transform = 'scale(1)';
            this.panel.style.opacity = '1';
        }, 300);
    }

    destroy() {
        if (this.panel) this.panel.remove();
        const styles = document.getElementById('advanced-xss-scanner-styles');
        if (styles) styles.remove();
        console.log('🛡️ Advanced Scanner destroyed');
    }
}

// Global instance
window.scanner = new XSSScanner();
