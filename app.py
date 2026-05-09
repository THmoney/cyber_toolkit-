from flask import Flask, request, jsonify, render_template_string
import requests
import re
import hashlib

app = Flask(__name__)

HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Neo's Cyber Toolkit</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0a0a0a; color: #00ff41; font-family: 'Courier New', monospace; padding: 20px; }
        h1 { text-align: center; font-size: 1.4em; color: #00ff41; margin-bottom: 5px; text-shadow: 0 0 10px #00ff41; }
        .subtitle { text-align: center; color: #666; font-size: 0.8em; margin-bottom: 25px; }
        .card { background: #111; border: 1px solid #00ff4133; border-radius: 8px; padding: 15px; margin-bottom: 15px; }
        .card h2 { color: #00ff41; font-size: 0.95em; margin-bottom: 12px; border-bottom: 1px solid #00ff4122; padding-bottom: 8px; }
        input { width: 100%; background: #0a0a0a; border: 1px solid #00ff4155; color: #00ff41; padding: 10px; border-radius: 5px; font-family: 'Courier New', monospace; font-size: 0.85em; margin-bottom: 10px; }
        button { width: 100%; background: #00ff4122; border: 1px solid #00ff41; color: #00ff41; padding: 10px; border-radius: 5px; font-family: 'Courier New', monospace; cursor: pointer; font-size: 0.85em; }
        button:hover { background: #00ff4144; }
        .result { margin-top: 12px; padding: 10px; background: #0a0a0a; border-radius: 5px; border-left: 3px solid #00ff41; font-size: 0.82em; line-height: 1.6; display: none; }
        .danger { border-left-color: #ff3333; color: #ff3333; }
        .warning { border-left-color: #ffaa00; color: #ffaa00; }
        .safe { border-left-color: #00ff41; color: #00ff41; }
        .loader { text-align: center; display: none; color: #00ff41; margin-top: 10px; }
    </style>
</head>
<body>
    <h1>[ NEO'S CYBER TOOLKIT ]</h1>
    <p class="subtitle">Cybersecurity Analysis Dashboard</p>

    <div class="card">
        <h2>🔍 IP Threat Analyzer</h2>
        <input type="text" id="ip" placeholder="Enter IP address...">
        <button onclick="checkIP()">ANALYZE IP</button>
        <div class="loader" id="ip-loader">Scanning...</div>
        <div class="result" id="ip-result"></div>
    </div>

    <div class="card">
        <h2>🔐 Password Strength Checker</h2>
        <input type="text" id="password" placeholder="Enter password...">
        <button onclick="checkPassword()">ANALYZE PASSWORD</button>
        <div class="result" id="pass-result"></div>
    </div>

    <div class="card">
        <h2>💀 Breach Checker</h2>
        <input type="text" id="breach" placeholder="Enter password to check...">
        <button onclick="checkBreach()">CHECK BREACHES</button>
        <div class="loader" id="breach-loader">Checking databases...</div>
        <div class="result" id="breach-result"></div>
    </div>

    <div class="card">
        <h2>🌐 Phishing URL Detector</h2>
        <input type="text" id="url" placeholder="Enter URL...">
        <button onclick="checkURL()">SCAN URL</button>
        <div class="result" id="url-result"></div>
    </div>

<script>
async function checkIP() {
    const ip = document.getElementById('ip').value;
    if (!ip) return;
    document.getElementById('ip-loader').style.display = 'block';
    document.getElementById('ip-result').style.display = 'none';
    const res = await fetch('/api/ip?ip=' + ip);
    const data = await res.json();
    const el = document.getElementById('ip-result');
    document.getElementById('ip-loader').style.display = 'none';
    el.style.display = 'block';
    el.className = 'result ' + (data.threat ? 'danger' : 'safe');
    el.innerHTML = data.output;
}

function checkPassword() {
    const pw = document.getElementById('password').value;
    if (!pw) return;
    const el = document.getElementById('pass-result');
    el.style.display = 'block';
    let score = 0;
    let tips = [];
    if (pw.length >= 12) score++; else tips.push('Use at least 12 characters');
    if (/[A-Z]/.test(pw)) score++; else tips.push('Add uppercase letters');
    if (/[a-z]/.test(pw)) score++; else tips.push('Add lowercase letters');
    if (/[0-9]/.test(pw)) score++; else tips.push('Add numbers');
    if (/[^A-Za-z0-9]/.test(pw)) score++; else tips.push('Add special characters (!@#$)');
    const levels = ['CRITICAL', 'WEAK', 'MODERATE', 'STRONG', 'VERY STRONG', 'UNBREAKABLE'];
    const classes = ['danger', 'danger', 'warning', 'safe', 'safe', 'safe'];
    el.className = 'result ' + classes[score];
    el.innerHTML = `Strength: <b>${levels[score]}</b><br>${tips.length ? 'Tips: ' + tips.join(' | ') : '✅ Excellent password!'}`;
}

async function checkBreach() {
    const pw = document.getElementById('breach').value;
    if (!pw) return;
    document.getElementById('breach-loader').style.display = 'block';
    document.getElementById('breach-result').style.display = 'none';
    const res = await fetch('/api/breach?password=' + encodeURIComponent(pw));
    const data = await res.json();
    const el = document.getElementById('breach-result');
    document.getElementById('breach-loader').style.display = 'none';
    el.style.display = 'block';
    el.className = 'result ' + (data.breached ? 'danger' : 'safe');
    el.innerHTML = data.output;
}

function checkURL() {
    const url = document.getElementById('url').value;
    if (!url) return;
    const el = document.getElementById('url-result');
    el.style.display = 'block';
    let risk = 0;
    let flags = [];
    const suspicious = ['login', 'verify', 'secure', 'account', 'update', 'confirm', 'banking', 'paypal', 'apple', 'amazon'];
    const shorteners = ['bit.ly', 'tinyurl', 't.co', 'goo.gl', 'ow.ly'];
    if (!url.startsWith('https://')) { risk++; flags.push('No HTTPS encryption'); }
    if (shorteners.some(s => url.includes(s))) { risk++; flags.push('URL shortener detected'); }
    if ((url.match(/-/g) || []).length > 3) { risk++; flags.push('Excessive hyphens'); }
    if (suspicious.some(w => url.toLowerCase().includes(w))) { risk++; flags.push('Suspicious keywords found'); }
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) { risk += 2; flags.push('IP address used instead of domain'); }
    el.className = 'result ' + (risk >= 3 ? 'danger' : risk >= 1 ? 'warning' : 'safe');
    el.innerHTML = risk >= 3 ? `⚠️ HIGH RISK — ${flags.join(' | ')}` : risk >= 1 ? `⚡ SUSPICIOUS — ${flags.join(' | ')}` : '✅ URL appears safe';
}
</script>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(HTML)

@app.route('/api/ip')
def check_ip():
    ip = request.args.get('ip', '')
    try:
        r = requests.get(f'http://ip-api.com/json/{ip}', timeout=5).json()
        threat = r.get('proxy', False) or r.get('hosting', False)
        output = f"""
        IP: {r.get('query')}<br>
        Country: {r.get('country')}<br>
        City: {r.get('city')}<br>
        ISP: {r.get('isp')}<br>
        Proxy/VPN: {'⚠️ YES' if r.get('proxy') else '✅ No'}<br>
        Hosting/DC: {'⚠️ YES' if r.get('hosting') else '✅ No'}<br>
        Status: {'🔴 SUSPICIOUS' if threat else '🟢 CLEAN'}
        """
        return jsonify({'output': output, 'threat': threat})
    except:
        return jsonify({'output': 'Error — check IP and try again', 'threat': False})

@app.route('/api/breach')
def check_breach():
    password = request.args.get('password', '')
    try:
        sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1[:5], sha1[5:]
        r = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}', timeout=5)
        hashes = r.text.splitlines()
        for h in hashes:
            if h.split(':')[0] == suffix:
                count = h.split(':')[1]
                return jsonify({'output': f'🔴 PWNED! Found {count} times in data breaches. Change this password immediately.', 'breached': True})
        return jsonify({'output': '✅ Good news — not found in any known breaches.', 'breached': False})
    except:
        return jsonify({'output': 'Error connecting to breach database', 'breached': False})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
