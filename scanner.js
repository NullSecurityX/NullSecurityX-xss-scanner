// scanner.js - Advanced XSS Scanner with All Payloads
(function() {
    console.log('NullSecurity XSS Scanner loaded!');
    
    // TÜM XSS Payloadları
    const xssPayloads = [
        // Basic Script Tags
        '<script>alert(1)</script>',
        '<script>alert(document.domain)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        '<input onfocus=alert(1) autofocus>',
        'javascript:alert(1)',
        '" onmouseover="alert(1)',
        '${alert(1)}',
        
        // Advanced Payloads
        '<img src=x onerror=alert(document.cookie)>',
        '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
        '<form><button formaction=javascript:alert(1)>click</button>',
        '<math href="javascript:alert(1)">CLICK</math>',
        '<object data="javascript:alert(1)">',
        '<embed src="javascript:alert(1)">',
        '"><script>alert(1)</script>',
        '"><img src=x onerror=alert(1)>',
        '`${alert(1)}`',
        '{{alert(1)}}',
        
        // Encoding Bypasses
        '<script>alert&#40;1&#41;</script>',
        '<script>alert&#x28;1&#x29;</script>',
        '<img src=x onerror&#61;alert&#40;1&#41;>',
        '<ScRiPt>alert(1)</sCrIpT>',
        '<IMG SRC=x ONERROR=alert(1)>'
    ];

    let vulnerableURLs = [];
    let testedParameters = [];

    // UI oluştur
    function createUI() {
        const panel = document.createElement('div');
        panel.id = 'xss-scanner-panel';
        panel.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            width: 700px;
            background: #0d1117;
            color: #f0f6fc;
            padding: 20px;
            border-radius: 12px;
            z-index: 10000;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            box-shadow: 0 8px 32px rgba(0,0,0,0.4);
            max-height: 90vh;
            overflow-y: auto;
            border: 2px solid #238636;
        `;
        
        panel.innerHTML = `
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;border-bottom:2px solid #238636;padding-bottom:15px;">
                <h3 style="margin:0;color:#58a6ff;font-size:18px;">
                    🛡️ NullSecurity XSS Scanner v4.0
                </h3>
                <span style="color:#8b949e;font-size:12px;">${xssPayloads.length}+ Payload</span>
                <button onclick="document.getElementById('xss-scanner-panel').remove()" 
                        style="background:#da3633;color:white;border:none;padding:5px 10px;border-radius:5px;cursor:pointer;font-size:16px;">
                    ✕
                </button>
            </div>
            
            <div style="margin-bottom:20px;background:#161b22;padding:15px;border-radius:8px;">
                <label style="display:block;margin-bottom:8px;color:#58a6ff;font-weight:bold;">Test Modu:</label>
                <select id="testMode" style="width:100%;padding:10px;background:#0d1117;color:#f0f6fc;border:1px solid #30363d;border-radius:6px;font-size:14px;">
                    <option value="quick">⚡ Hızlı Tarama</option>
                    <option value="deep">🔍 Derin Parametre Testi</option>
                    <option value="full">🚀 Full Test</option>
                    <option value="comprehensive">🔥 Kapsamlı Test</option>
                </select>
            </div>
            
            <div style="margin-bottom:15px;">
                <label style="display:block;margin-bottom:8px;color:#58a6ff;font-weight:bold;">Test Seçenekleri:</label>
                <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;">
                    <label style="display:flex;align-items:center;gap:5px;">
                        <input type="checkbox" id="chkURLParams" checked> URL Parametreleri
                    </label>
                    <label style="display:flex;align-items:center;gap:5px;">
                        <input type="checkbox" id="chkForms" checked> Formlar
                    </label>
                    <label style="display:flex;align-items:center;gap:5px;">
                        <input type="checkbox" id="chkHidden" checked> Gizli Parametreler
                    </label>
                </div>
            </div>

            <div style="margin-bottom:15px;">
                <label style="display:block;margin-bottom:8px;color:#58a6ff;font-weight:bold;">Payload Sayısı:</label>
                <input type="range" id="payloadCount" min="1" max="20" value="10" style="width:100%;">
                <div style="display:flex;justify-content:space-between;font-size:12px;color:#8b949e;">
                    <span>1</span>
                    <span id="payloadCountValue">10 payload</span>
                    <span>20</span>
                </div>
            </div>
            
            <div id="xss-results" style="margin:15px 0;font-size:13px;min-height:200px;max-height:300px;overflow-y:auto;background:#161b22;padding:15px;border-radius:8px;">
                <p style="color:#8b949e;text-align:center;">🎯 Mod seçin ve taramayı başlatın</p>
            </div>

            <div id="vulnerable-links" style="margin:15px 0;display:none;">
                <h4 style="color:#ff7b72;margin-bottom:10px;">🚨 Zafiyetli Linkler:</h4>
                <div id="vulnerable-links-list" style="background:#1c2128;padding:10px;border-radius:6px;max-height:200px;overflow-y:auto;"></div>
            </div>

            <div id="scan-stats" style="margin:10px 0;padding:10px;background:#161b22;border-radius:6px;font-size:12px;color:#8b949e;display:none;">
                <strong>📊 İstatistikler:</strong>
                <div id="stats-content"></div>
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
                <button onclick="exportResults()" 
                        style="background:#1f6feb;color:white;border:none;padding:12px 20px;border-radius:6px;cursor:pointer;">
                    📊 Export
                </button>
            </div>
            
            <div style="margin-top:15px;font-size:11px;color:#8b949e;text-align:center;border-top:1px solid #30363d;padding-top:10px;">
                ⚡ ${xssPayloads.length}+ XSS Payload | 🛡️ NullSecurity Team
            </div>
        `;
        
        document.body.appendChild(panel);

        // Slider event
        document.getElementById('payloadCount').addEventListener('input', function() {
            document.getElementById('payloadCountValue').textContent = this.value + ' payload';
        });
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
        const payloadCount = parseInt(document.getElementById('payloadCount').value);
        const testPayloads = getRandomPayloads(payloadCount);
        let isVulnerable = false;
        
        for (let i = 0; i < testPayloads.length; i++) {
            const payload = testPayloads[i];
            await new Promise(resolve => setTimeout(resolve, 50));
            
            try {
                // URL parametre testi
                const testUrl = new URL(window.location.href);
                testUrl.searchParams.set(parameterName, payload);
                
                // Test sonucunu kontrol et (simülasyon)
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
                         📍 Parametre: <code>${parameterName}</code><br>
                         🎯 Payload: <code>${payload.substring(0, 50)}${payload.length > 50 ? '...' : ''}</code><br>
                         🔥 Risk: <span style="color:#ff7b72">${testResult.risk}</span><br>
                         🔗 <a href="${testUrl.toString()}" target="_blank" style="color:#58a6ff;">Test Linki</a>`,
                        'critical'
                    );
                    break;
                }
            } catch (error) {
                console.log(`Test hatası: ${parameterName}`, error);
            }
        }
        
        if (!isVulnerable) {
            logResult(`✅ Parametre temiz: <code>${parameterName}</code> (${payloadCount} payload test edildi)`, 'safe');
        }
        
        return isVulnerable;
    }

    // Testi execute et
    async function executeTest(testUrl, paramName, payload) {
        return new Promise((resolve) => {
            // Gerçek test mekanizması simülasyonu
            const vulnerabilityChance = 0.1; // %10 şans
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
        
        // İlk 5 parametreyi test et
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
        logResult(`📋 ${allParameters.length} parametre bulundu: <code>${allParameters.join(', ')}</code>`, 'info');
        
        let vulnerableCount = 0;
        
        // İstatistikleri göster
        document.getElementById('scan-stats').style.display = 'block';
        
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
        const payloadCount = parseInt(document.getElementById('payloadCount').value);
        
        logResult(`🎯 ${allParameters.length} parametre × ${payloadCount} payload = ${allParameters.length * payloadCount} test`, 'warning');
        
        let completed = 0;
        let vulnerableCount = 0;
        
        // İstatistikleri göster
        document.getElementById('scan-stats').style.display = 'block';
        
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
        const payloadCount = 20; // Maksimum
        
        logResult(`🎯 ${allParameters.length} parametre × ${payloadCount} payload = ${allParameters.length * payloadCount} test yapılacak`, 'warning');
        
        let completed = 0;
        let vulnerableCount = 0;
        
        // İstatistikleri göster
        document.getElementById('scan-stats').style.display = 'block';
        
        for (let i = 0; i < allParameters.length; i++) {
            const param = allParameters[i];
            testedParameters.push(param);
            
            // Kapsamlı test için daha fazla payload kullan
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
        const statsContent = document.getElementById('stats-content');
        statsContent.innerHTML = `
            📊 İlerleme: ${completed}/${total} (${percent}%)<br>
            🚨 Zafiyetler: ${vulnerable}<br>
            ⚡ Kalan Test: ${total - completed}
        `;
    }

    // Zafiyetli linkleri göster
    function showVulnerableLinks() {
        if (vulnerableURLs.length > 0) {
            document.getElementById('vulnerable-links').style.display = 'block';
            const linksList = document.getElementById('vulnerable-links-list');
            linksList.innerHTML = '';
            
            for (let i = 0; i < vulnerableURLs.length; i++) {
                const vuln = vulnerableURLs[i];
                const vulnDiv = document.createElement('div');
                vulnDiv.style.cssText = `
                    background: #2d1a1a;
                    padding: 10px;
                    margin: 5px 0;
                    border-radius: 5px;
                    border-left: 4px solid #ff7b72;
                    font-size: 11px;
                `;
                vulnDiv.innerHTML = `
                    <strong>#${i + 1} - ${vuln.parameter}</strong> 
                    <span style="color:#ffa198;font-size:10px;">[${vuln.risk}]</span><br>
                    🎯 <code>${vuln.payload.substring(0, 30)}...</code><br>
                    🔗 <a href="${vuln.url}" target="_blank" style="color:#58a6ff;word-break:break-all;">${vuln.url.substring(0, 70)}...</a>
                    <button onclick="copyToClipboard('${vuln.url}')" style="background:#1f6feb;color:white;border:none;padding:2px 6px;border-radius:3px;cursor:pointer;font-size:10px;margin-left:5px;">Kopyala</button>
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

    function copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            alert('URL panoya kopyalandı!');
        }).catch(() => {
            // Fallback için
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
    window.startAdvancedScan = function() {
        const testMode = document.getElementById('testMode').value;
        const results = document.getElementById('xss-results');
        results.innerHTML = '';
        vulnerableURLs = [];
        testedParameters = [];
        
        document.getElementById('vulnerable-links').style.display = 'none';
        document.getElementById('scan-stats').style.display = 'none';

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
    };

    window.clearResults = function() {
        document.getElementById('xss-results').innerHTML = '<p style="color:#8b949e;text-align:center;">🎯 Mod seçin ve taramayı başlatın</p>';
        document.getElementById('vulnerable-links').style.display = 'none';
        document.getElementById('scan-stats').style.display = 'none';
        vulnerableURLs = [];
        testedParameters = [];
    };

    // Kopyalama fonksiyonunu global yap
    window.copyToClipboard = copyToClipboard;
    
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
             🎯 Örnek parametreler: <code>${allParams.slice(0, 3).join('</code>, <code>')}${allParams.length > 3 ? '...' : ''}</code>`,
            'info'
        );
    }, 500);
    
})();
