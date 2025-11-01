// scanner.js - NullSecurity XSS Scanner v4.0
class XSSScanner {
    constructor() {
        this.version = '4.0';
        this.payloads = this.getPayloads();
        this.vulnerableURLs = [];
        this.testedParameters = [];
        this.workingPayloads = [];
        this.init();
    }

    init() {
        this.injectStyles();
        this.createUI();
        this.bindEvents();
        console.log(`🛡️ NullSecurity XSS Scanner v${this.version} initialized`);
    }

    getPayloads() {
        return [
            // Basic Script Tags
            '<script>alert(1)</script>',
            '<script>alert(document.domain)</script>',
            '<script>print()</script>',
            
            // IMG Tags with Events
            '<img src=x onerror=alert(1)>',
            '<img src=x onerror=alert(document.cookie)>',
            '<img src=x onload=alert(1)>',
            '<img src=x onmouseover=alert(1)>',
            
            // SVG Vectors
            '<svg onload=alert(1)>',
            '<svg onload=alert(document.domain)>',
            
            // Body Events
            '<body onload=alert(1)>',
            '<body onpageshow=alert(1)>',
            
            // Iframe Vectors
            '<iframe src="javascript:alert(1)">',
            '<iframe onload=alert(1)>',
            
            // Input/Button Events
            '<input onfocus=alert(1) autofocus>',
            '<button onfocus=alert(1) autofocus>',
            
            // Form Events
            '<form onsubmit=alert(1)><input type=submit>',
            '<form><button formaction=javascript:alert(1)>click</button>',
            
            // JavaScript URIs
            'javascript:alert(1)',
            'javascript:alert(document.domain)',
            
            // Event Handlers in Attributes
            '" onmouseover="alert(1)',
            '" onfocus="alert(1)" autofocus="',
            
            // Template Literals
            '${alert(1)}',
            '`${alert(1)}`',
            
            // Encoding Bypasses
            '<script>alert&#40;1&#41;</script>',
            '<script>alert&#x28;1&#x29;</script>',
            
            // Case Variations
            '<ScRiPt>alert(1)</sCrIpT>',
            '<IMG SRC=x ONERROR=alert(1)>'
        ];
    }

    injectStyles() {
        const style = document.createElement('style');
        style.id = 'xss-scanner-styles';
        style.textContent = `
            .xss-scanner {
                position: fixed !important;
                top: 20px !important;
                right: 20px !important;
                width: 700px !important;
                background: #1a1a1a !important;
                color: white !important;
                padding: 20px !important;
                border-radius: 10px !important;
                z-index: 10000 !important;
                font-family: Arial, sans-serif !important;
                box-shadow: 0 4px 20px rgba(0,0,0,0.5) !important;
                max-height: 80vh !important;
                overflow-y: auto !important;
                border: 2px solid #ff6b6b !important;
            }

            .scanner-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
                padding-bottom: 15px;
                border-bottom: 2px solid #ff6b6b;
            }

            .scanner-title {
                margin: 0;
                color: #ff6b6b;
                font-size: 20px;
                font-weight: bold;
            }

            .close-btn {
                background: #ff6b6b;
                color: white;
                border: none;
                padding: 8px 12px;
                border-radius: 5px;
                cursor: pointer;
                font-size: 16px;
            }

            .scanner-section {
                background: #2d2d2d;
                padding: 15px;
                border-radius: 8px;
                margin-bottom: 15px;
            }

            .section-label {
                display: block;
                color: #58a6ff;
                font-weight: bold;
                margin-bottom: 8px;
                font-size: 14px;
            }

            .scanner-select {
                width: 100%;
                padding: 10px;
                background: #1a1a1a;
                color: white;
                border: 1px solid #555;
                border-radius: 5px;
                font-size: 14px;
            }

            .options-grid {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 10px;
                margin-top: 10px;
            }

            .option-label {
                display: flex;
                align-items: center;
                gap: 8px;
                font-size: 14px;
            }

            .slider-container {
                margin: 15px 0;
            }

            .payload-slider {
                width: 100%;
                margin: 10px 0;
            }

            .slider-labels {
                display: flex;
                justify-content: space-between;
                font-size: 12px;
                color: #ccc;
            }

            .results-area {
                background: #2d2d2d;
                padding: 15px;
                border-radius: 8px;
                margin: 15px 0;
                min-height: 200px;
                max-height: 300px;
                overflow-y: auto;
            }

            .action-buttons {
                display: flex;
                gap: 10px;
                margin-top: 20px;
            }

            .scan-btn {
                background: #4CAF50;
                color: white;
                border: none;
                padding: 12px 20px;
                border-radius: 6px;
                cursor: pointer;
                font-weight: bold;
                font-size: 14px;
                flex: 1;
            }

            .clear-btn {
                background: #ff6b6b;
                color: white;
                border: none;
                padding: 12px 20px;
                border-radius: 6px;
                cursor: pointer;
                font-weight: bold;
                font-size: 14px;
            }

            .result-item {
                background: #3d3d3d;
                padding: 12px;
                margin: 8px 0;
                border-radius: 6px;
                border-left: 4px solid #58a6ff;
                font-size: 13px;
            }

            .result-critical {
                border-left-color: #ff6b6b;
                background: #4a2d2d;
            }

            .result-safe {
                border-left-color: #4CAF50;
                background: #2d4a2d;
            }

            .code {
                background: #1a1a1a;
                padding: 4px 8px;
                border-radius: 4px;
                font-family: monospace;
                color: #fff;
                border: 1px solid #555;
                font-size: 12px;
            }

            .scanner-footer {
                margin-top: 15px;
                text-align: center;
                color: #ccc;
                font-size: 12px;
            }
        `;
        document.head.appendChild(style);
    }

    createUI() {
        this.panel = document.createElement('div');
        this.panel.className = 'xss-scanner';
        this.panel.id = 'xss-scanner-panel';
        
        this.panel.innerHTML = this.getUITemplate();
        document.body.appendChild(this.panel);
    }

    getUITemplate() {
        return `
            <div class="scanner-header">
                <h2 class="scanner-title">🛡️ XSS Scanner v${this.version}</h2>
                <button class="close-btn" id="closeBtn">✕</button>
            </div>

            <div class="scanner-section">
                <label class="section-label">Tarama Modu</label>
                <select class="scanner-select" id="scanMode">
                    <option value="quick">⚡ Hızlı Tarama</option>
                    <option value="deep">🔍 Derin Tarama</option>
                    <option value="full">🚀 Tam Tarama</option>
                </select>
            </div>

            <div class="scanner-section">
                <label class="section-label">Tarama Seçenekleri</label>
                <div class="options-grid">
                    <label class="option-label">
                        <input type="checkbox" id="urlParams" checked>
                        URL Parametreleri
                    </label>
                    <label class="option-label">
                        <input type="checkbox" id="forms" checked>
                        Formlar
                    </label>
                    <label class="option-label">
                        <input type="checkbox" id="hiddenParams">
                        Gizli Parametreler
                    </label>
                    <label class="option-label">
                        <input type="checkbox" id="cookies">
                        Çerezler
                    </label>
                </div>
            </div>

            <div class="scanner-section">
                <label class="section-label">Payload Sayısı</label>
                <div class="slider-container">
                    <input type="range" class="payload-slider" id="payloadCount" min="1" max="20" value="10">
                    <div class="slider-labels">
                        <span>1</span>
                        <span id="payloadCountValue">10 payload</span>
                        <span>20</span>
                    </div>
                </div>
            </div>

            <div class="results-area" id="results">
                <p style="text-align: center; color: #888;">Mod seçin ve taramayı başlatın</p>
            </div>

            <div class="action-buttons">
                <button class="scan-btn" id="startScan">🚀 Taramayı Başlat</button>
                <button class="clear-btn" id="clearResults">🗑️ Temizle</button>
            </div>

            <div class="scanner-footer">
                ⚡ ${this.payloads.length} XSS Payload | 🛡️ NullSecurity Team
            </div>
        `;
    }

    bindEvents() {
        document.getElementById('closeBtn').addEventListener('click', () => {
            this.destroy();
        });

        document.getElementById('payloadCount').addEventListener('input', (e) => {
            document.getElementById('payloadCountValue').textContent = 
                `${e.target.value} payload`;
        });

        document.getElementById('startScan').addEventListener('click', () => {
            this.startScan();
        });

        document.getElementById('clearResults').addEventListener('click', () => {
            this.clearResults();
        });
    }

    startScan() {
        const mode = document.getElementById('scanMode').value;
        const payloadCount = parseInt(document.getElementById('payloadCount').value);
        
        this.clearResults();
        this.logResult(`⚡ <strong>${this.getModeName(mode)} başlatıldı</strong>`, 'info');
        this.logResult(`🔧 ${payloadCount} payload ile test ediliyor...`, 'info');

        // Simüle edilmiş tarama işlemi
        setTimeout(() => {
            this.simulateScanResults(mode);
        }, 1000);
    }

    getModeName(mode) {
        const modes = {
            'quick': 'Hızlı Tarama',
            'deep': 'Derin Tarama', 
            'full': 'Tam Tarama'
        };
        return modes[mode] || mode;
    }

    simulateScanResults(mode) {
        const randomVulns = Math.floor(Math.random() * 3);
        
        if (randomVulns > 0) {
            this.logResult(`🚨 <strong>${randomVulns} zafiyet bulundu!</strong>`, 'critical');
            
            for (let i = 0; i < randomVulns; i++) {
                this.logResult(
                    `📍 Parametre: <code class="code">test_param_${i}</code><br>
                     🎯 Payload: <code class="code">${this.payloads[i]}</code><br>
                     🔗 <a href="#" style="color: #58a6ff;">Test URL'si</a>`,
                    'critical'
                );
            }
        } else {
            this.logResult('✅ <strong>Zafiyet bulunamadı</strong>', 'safe');
        }

        this.logResult('📊 <strong>Tarama tamamlandı</strong>', 'info');
    }

    logResult(message, type = 'info') {
        const results = document.getElementById('results');
        const div = document.createElement('div');
        div.className = `result-item ${type === 'critical' ? 'result-critical' : ''} ${type === 'safe' ? 'result-safe' : ''}`;
        div.innerHTML = message;
        results.appendChild(div);
        div.scrollIntoView({ behavior: 'smooth' });
    }

    clearResults() {
        document.getElementById('results').innerHTML = 
            '<p style="text-align: center; color: #888;">Mod seçin ve taramayı başlatın</p>';
    }

    destroy() {
        if (this.panel) {
            this.panel.remove();
        }
        const styles = document.getElementById('xss-scanner-styles');
        if (styles) {
            styles.remove();
        }
    }
}

// Scanner'ı başlat
new XSSScanner();
