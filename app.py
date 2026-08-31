import datetime
import hashlib
import ipaddress
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import time
import whois
import socket
from celery import Celery
from flask import Flask, jsonify, render_template, request, Response
from flask_socketio import SocketIO
from google import genai
from openai import OpenAI
import requests
from celery.schedules import crontab

# Detect Host Operating System
IS_WINDOWS = platform.system().lower() == "windows"

# Initialize Flask and SocketIO
app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Initialize Celery
redis_url = os.environ.get('REDIS_URL', 'redis://127.0.0.1:6379/0' if IS_WINDOWS else 'redis://redis:6379/0')
celery = Celery(app.name, broker=redis_url, backend=redis_url)
celery.conf.update(result_backend=redis_url, broker_url=redis_url)

start_time = time.time()

celery.conf.beat_schedule = {
    'sentinel-automated-fim-scan': {
        'task': 'app.automated_background_fim',
        'schedule': crontab(minute='*/15'), # Runs every 15 minutes
    },
}

# Initialize AI & Threat Intel Clients
gemini_api_key = os.environ.get("GEMINI_API_KEY")
copilot_api_key = os.environ.get("COPILOT_API_KEY")
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")

gemini_client = genai.Client(api_key=gemini_api_key) if gemini_api_key else None
copilot_client = OpenAI(api_key=copilot_api_key) if copilot_api_key else None


def init_db():
    with sqlite3.connect('security_audit.db') as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                module TEXT,
                target TEXT,
                ai_analysis TEXT,
                risk_score INTEGER
            )
        ''')
        conn.commit()

init_db()


def log_audit(timestamp, module, target, ai_analysis, risk_score):
    try:
        with sqlite3.connect('security_audit.db') as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO audit_logs (timestamp, module, target, ai_analysis, risk_score) VALUES (?, ?, ?, ?, ?)",
                (timestamp, module, target, ai_analysis, risk_score)
            )
            conn.commit()
    except Exception as e:
        print(f"Audit log database error: {e}")


def sanitize_target(target):
    if not target or target.strip().startswith('-'):
        return "127.0.0.1"
    clean = re.sub(r'[^a-zA-Z0-9.\-_:/]', '', target.strip())
    return clean if clean else "127.0.0.1"


def check_ip_reputation(target_ip):
    try:
        clean_ip = target_ip.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]
        ip_obj = ipaddress.ip_address(clean_ip)
        if ip_obj.is_private or ip_obj.is_loopback:
            return f"[Threat Intel] Target '{target_ip}' is a Private/Loopback RFC-1918 address. No external threat history."
    except ValueError:
        return ""

    if not ABUSEIPDB_API_KEY:
        return "[Threat Intel] ABUSEIPDB_API_KEY not configured. Skipping external reputation lookup."

    try:
        url = 'https://api.abuseipdb.com/api/v2/check'
        params = {'ipAddress': clean_ip, 'maxAgeInDays': '90'}
        headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
        
        resp = requests.get(url, headers=headers, params=params, timeout=4)
        if resp.status_code == 200:
            data = resp.json().get('data', {})
            score = data.get('abuseConfidenceScore', 0)
            reports = data.get('totalReports', 0)
            country = data.get('countryCode', 'Unknown')
            usage = data.get('usageType', 'Unknown')
            return f"[Threat Intel] Abuse Score: {score}% | Reports: {reports} | Country: {country} | Type: {usage}"
    except Exception as e:
        return f"[Threat Intel Error: {str(e)}]"
    
    return ""


def evaluate_threat_level(module_name, output_text, target=""):
    intel_context = check_ip_reputation(target) if target else ""
    enriched_output = f"{intel_context}\n\n{output_text}" if intel_context else output_text

    ghost_prompt = (
        f"Provide a threat assessment for the following scan output. "
        f"You are GHOST, an elite Red Team offensive security specialist. "
        f"Analyze this raw output from module '{module_name}':\n\n{enriched_output}\n\n"
        "Provide your analysis in this exact format:\n"
        "[SCORE: <0-100>]\n"
        "MITRE ATT&CK: [List relevant technique IDs like T1046, T1021]\n"
        "EXPLOIT PATH: <Concise explanation of how an attacker would exploit this target>\n"
    )

    aegis_prompt = (
        f"You are AEGIS, a Tier-3 Blue Team Security Operations defender. "
        f"Analyze this raw output from module '{module_name}':\n\n{enriched_output}\n\n"
        "Provide your analysis in this exact format:\n"
        "[SCORE: <0-100>]\n"
        "DEFENSE POSTURE: <Telemetry analysis and blind spots>\n"
        "REMEDIATION SCRIPT:\n"
        "```bash\n"
        "# Copy-pasteable shell/PowerShell commands to harden this finding\n"
        "```\n"
        "SIGMA RULE:\n"
        "```yaml\n"
        "# Minimal Sigma detection rule for SIEM\n"
        "```"
    )

    ghost_result = "Ghost Engine unavailable."
    aegis_result = "Aegis Engine unavailable."
    ghost_score = None
    aegis_score = None

    if copilot_client:
        try:
            copilot_resp = copilot_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": ghost_prompt}],
                temperature=0.2
            )
            ghost_result = copilot_resp.choices[0].message.content
            match = re.search(r'\[SCORE:\s*(\d+)\]', ghost_result)
            if match:
                ghost_score = int(match.group(1))
        except Exception as e:
            ghost_result = f"Ghost evaluation error: {str(e)}"

    if gemini_client:
        valid_models = ['gemini-3.6-flash', 'gemini-3.5-flash', 'gemini-3.7-flash']
        for model_name in valid_models:
            try:
                chat = gemini_client.chats.create(model=model_name)
                gemini_resp = chat.send_message(aegis_prompt)
                aegis_result = gemini_resp.text
                match = re.search(r'\[SCORE:\s*(\d+)\]', aegis_result)
                if match:
                    aegis_score = int(match.group(1))
                break
            except Exception as e:
                aegis_result = f"Aegis error ({model_name}): {str(e)}"
                if "503" in str(e) or "429" in str(e):
                    time.sleep(1)
                    continue

    scores = [s for s in [ghost_score, aegis_score] if s is not None]
    consensus = int(sum(scores) / len(scores)) if scores else 0

    return (
        f"[SCORE: {consensus}]\n\n"
        f"🔴 === GHOST (RED TEAM EXPLOIT ANALYSIS) ===\n{ghost_result}\n\n"
        f"🔵 === AEGIS (BLUE TEAM DEFENSE & REMEDIATION) ===\n{aegis_result}"
    )


def dispatch_soar_alert(module, target, score, analysis):
    webhook_url = os.environ.get("SOAR_WEBHOOK_URL")
    if not webhook_url or score < 50:
        return

    payload = {
        "content": f"🚨 **Ghost-Sentinel Alert** [Score: {score}/100]\n"
                   f"**Module:** {module} | **Target:** {target}\n"
                   f"```yaml\n{analysis[:400]}...\n```"
    }
    try:
        requests.post(webhook_url, json=payload, timeout=5)
    except Exception as e:
        print(f"Webhook dispatch failed: {e}")


def calculate_sha256(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        return str(e)


def run_cmd(command_list, stdin_input=""):
    executable = command_list[0]
    if not shutil.which(executable):
        return f"Tool execution error: '{executable}' is not installed or not in system PATH on this host ({platform.system()})."

    socketio.emit('console_update', {'data': f"\n[+] Executing: {' '.join(command_list)}\n"})
    
    try:
        process = subprocess.Popen(
            command_list,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=False
        )
        
        output = []
        if stdin_input:
            process.stdin.write(stdin_input)
            process.stdin.close()
            
        for line in iter(process.stdout.readline, ''):
            socketio.emit('console_update', {'data': line})
            output.append(line)
            
        process.stdout.close()
        process.wait(timeout=15)
        
        return "".join(output) if output else "Command executed with no output."
    except Exception as e:
        err = f"Execution error: {str(e)}"
        socketio.emit('console_update', {'data': f"\n[-] {err}\n"})
        return err


def execute_pipeline(module, target, command_list, stdin_input=""):
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output = run_cmd(command_list, stdin_input=stdin_input)
    ai_analysis = evaluate_threat_level(module, output, target=target)
    match = re.search(r'\[SCORE:\s*(\d+)\]', ai_analysis)
    score = int(match.group(1)) if match else 0
    
    log_audit(current_time, module, target, ai_analysis, score)
    dispatch_soar_alert(module, target, score, ai_analysis)
    
    return jsonify({"time": current_time, "result": ai_analysis, "risk_score": score})


@celery.task(name='app.run_fim_scan')
def run_fim_scan(directory=None):
    if not directory:
        directory = os.environ.get('SCAN_DIR', os.getcwd())
    integrity_report = {}
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.py', '.sh', '.bat', '.ps1', '.conf', '.json')):
                fullpath = os.path.join(root, file)
                integrity_report[fullpath] = calculate_sha256(fullpath)
    return integrity_report



@celery.task(name='app.automated_background_fim')
def automated_background_fim():
    """Runs silently in the background via Celery Beat."""
    base_dir = os.environ.get('SCAN_DIR', os.getcwd())
    integrity_report = {}
    
    for root, _, files in os.walk(base_dir):
        for file in files:
            if file.endswith(('.py', '.sh', '.bat', '.ps1', '.conf', '.json')):
                fullpath = os.path.join(root, file)
                integrity_report[fullpath] = calculate_sha256(fullpath)
    
    output_summary = (
        f"\n[AUTOSCAN] File Integrity Monitor Complete. OS: {platform.system()}.\n"
        f"Tracked {len(integrity_report)} critical scripts in {base_dir}.\n"
    )
    
    # Run through the Aegis threat evaluation
    ai_analysis = evaluate_threat_level("fim_autoscan", output_summary, target=base_dir)
    match = re.search(r'\[SCORE:\s*(\d+)\]', ai_analysis)
    score = int(match.group(1)) if match else 0
    
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Log to database and fire SOAR webhook silently
    log_audit(current_time, "fim_autoscan", base_dir, ai_analysis, score)
    dispatch_soar_alert("fim_autoscan", base_dir, score, ai_analysis)
    
    return f"Autoscan complete. Score: {score}"

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/telemetry')
def telemetry():
    uptime_seconds = int(time.time() - start_time)
    hours = uptime_seconds // 3600
    minutes = (uptime_seconds % 3600) // 60
    seconds = uptime_seconds % 60

    proc_count = 0
    try:
        if IS_WINDOWS:
            raw_tasks = subprocess.check_output(["tasklist"], text=True)
            proc_count = len(raw_tasks.strip().splitlines()) - 3
        else:
            proc_count = len(subprocess.check_output(["ps", "aux"]).splitlines())
    except Exception:
        proc_count = 10

    return jsonify({
        "uptime": f"{hours}h {minutes}m {seconds}s",
        "active_processes": max(proc_count, 1),
        "platform": platform.system()
    })


@app.route('/api/scan', methods=['POST'])
def scan():
    cmd = ["netstat", "-ano"] if IS_WINDOWS else ["ss", "-tuln"]
    return execute_pipeline("scan", "localhost", cmd)


@app.route('/api/discover', methods=['POST'])
def discover():
    data = request.get_json() or {}
    target = sanitize_target(data.get('target', '192.168.1.0/24'))
    nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
    cmd = [nmap_path, "-sn", target] if IS_WINDOWS and os.path.exists(nmap_path) else ["nmap", "-sn", target]
    return execute_pipeline("discover", target, cmd)


@app.route('/api/ports', methods=['POST'])
def ports():
    data = request.get_json() or {}
    target = sanitize_target(data.get('target', 'localhost'))
    nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
    cmd = [nmap_path, "-T4", "-F", target] if IS_WINDOWS and os.path.exists(nmap_path) else ["nmap", "-T4", "-F", target]
    return execute_pipeline("ports", target, cmd)


@app.route('/api/services', methods=['POST'])
def services():
    data = request.get_json() or {}
    target = sanitize_target(data.get('target', 'localhost'))
    nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
    cmd = [nmap_path, "-sV", "-p-", "--max-retries", "1", target] if IS_WINDOWS and os.path.exists(nmap_path) else ["nmap", "-sV", "-p-", "--max-retries", "1", target]
    return execute_pipeline("services", target, cmd)


@app.route('/api/dns', methods=['POST'])
def dns_lookup():
    data = request.get_json() or {}
    target = sanitize_target(data.get('target', 'example.com'))
    cmd = ["nslookup", target] if (IS_WINDOWS and not shutil.which("dig")) else ["dig", target]
    return execute_pipeline("dns", target, cmd)


@app.route('/api/whois', methods=['POST'])
def whois_lookup():
    data = request.get_json() or {}
    target = sanitize_target(data.get('target', 'example.com'))
    
    # Block local lookups immediately to prevent socket hangs
    if target in ["localhost", "127.0.0.1", "::1"]:
        output = "WHOIS error: Cannot perform public WHOIS registry query on local loopback target."
    else:
        socketio.emit('console_update', {'data': f"\n[*] Querying WHOIS registration for {target}...\n"})
        try:
            # Force a strict 5-second socket timeout so it never hangs for 20 mins
            socket.setdefaulttimeout(5)
            w = whois.whois(target)
            output = str(w)
        except Exception as e:
            output = f"WHOIS query timeout or error: {str(e)}"
        
    ai_analysis = evaluate_threat_level("whois", output, target=target)
    match = re.search(r'\[SCORE:\s*(\d+)\]', ai_analysis)
    score = int(match.group(1)) if match else 0
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    log_audit(current_time, "whois", target, ai_analysis, score)
    dispatch_soar_alert("whois", target, score, ai_analysis)
    
    return jsonify({"time": current_time, "result": ai_analysis, "risk_score": score})


@app.route('/api/traceroute', methods=['POST'])
def traceroute():
    data = request.get_json() or {}
    target = sanitize_target(data.get('target', '8.8.8.8'))
    cmd = ["tracert", "-h", "10", target] if IS_WINDOWS else ["traceroute", "-m", "10", target]
    return execute_pipeline("traceroute", target, cmd)


@app.route('/api/web', methods=['POST'])
def web_scan():
    data = request.get_json() or {}
    target = sanitize_target(data.get('target', 'localhost'))
    return execute_pipeline("web", target, ["nikto", "-h", target])


@app.route('/api/ssl', methods=['POST'])
def ssl_scan():
    data = request.get_json() or {}
    target = sanitize_target(data.get('target', 'localhost'))
    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]
    return execute_pipeline(
        "ssl",
        clean_target,
        ["openssl", "s_client", "-connect", f"{clean_target}:443", "-servername", clean_target],
        stdin_input=""
    )


@app.route('/api/smb', methods=['POST'])
def smb_enum():
    data = request.get_json() or {}
    target = sanitize_target(data.get('target', 'localhost'))
    if IS_WINDOWS:
        cmd = ["nmap", "-p", "445,139", "--script", "smb-enum-shares,smb-os-discovery", target]
    else:
        cmd = ["enum4linux", "-a", target] if shutil.which("enum4linux") else ["nmap", "-p", "445", "--script", "smb-enum-shares", target]
    return execute_pipeline("smb", target, cmd)


@app.route('/api/fim', methods=['POST'])
def trigger_fim():
    socketio.emit('console_update', {'data': "\n[*] Initializing File Integrity Hash Walk...\n"})
    try:
        base_dir = os.environ.get('SCAN_DIR', os.getcwd())
        integrity_report = {}
        
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file.endswith(('.py', '.sh', '.bat', '.ps1', '.conf', '.json', '.html')):
                    fullpath = os.path.join(root, file)
                    file_hash = calculate_sha256(fullpath)
                    integrity_report[fullpath] = file_hash
                    socketio.emit('console_update', {'data': f"[HASHED] {file} -> {file_hash[:16]}...\n"})
        
        output_summary = (
            f"\nFile Integrity Monitor (FIM) Complete. Host OS: {platform.system()}.\n"
            f"Tracked {len(integrity_report)} critical scripts in {base_dir}.\n"
        )
        
        socketio.emit('console_update', {'data': "\n[*] Sending hash baseline to Aegis for analysis...\n"})
        
        ai_analysis = evaluate_threat_level("fim", output_summary, target=base_dir)
        match = re.search(r'\[SCORE:\s*(\d+)\]', ai_analysis)
        score = int(match.group(1)) if match else 0
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        log_audit(current_time, "fim", base_dir, ai_analysis, score)
        dispatch_soar_alert("fim", base_dir, score, ai_analysis)
        
        return jsonify({"time": current_time, "result": ai_analysis, "risk_score": score})
    except Exception as e:
        err_msg = f"FIM Error: {str(e)}"
        socketio.emit('console_update', {'data': f"\n[-] {err_msg}\n"})
        return jsonify({"status": "error", "message": err_msg}), 500


@app.route('/api/compliance', methods=['POST'])
def run_compliance():
    socketio.emit('console_update', {'data': "\n[*] Initializing CIS/CJIS Baseline Compliance Audit...\n"})
    
    if IS_WINDOWS:
        cmd = [
            "powershell", "-Command", 
            "Get-MpComputerStatus | Select-Object AMServiceEnabled; "
            "Get-NetFirewallProfile | Select-Object Name, Enabled; "
            "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\USBSTOR' -Name Start -ErrorAction SilentlyContinue"
        ]
    else:
        cmd = ["bash", "-c", "ufw status || iptables -L; lsmod | grep usb-storage; sestatus || aa-status"]
        
    return execute_pipeline("compliance", "localhost", cmd)


@app.route('/api/rules/export', methods=['GET'])
def export_sigma_rules():
    try:
        with sqlite3.connect('security_audit.db') as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT timestamp, module, target, ai_analysis FROM audit_logs ORDER BY id DESC")
            rows = cursor.fetchall()
            
        sigma_bundle = "# Ghost-Sentinel Generated Sigma Detection Rules Bundle\n"
        sigma_bundle += f"# Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        sigma_bundle += "# -------------------------------------------------------------\n\n"
        
        extracted_count = 0
        for r in rows:
            analysis = r['ai_analysis'] or ""
            yaml_matches = re.findall(r'```yaml(.*?)```', analysis, re.DOTALL)
            for y in yaml_matches:
                extracted_count += 1
                sigma_bundle += f"# Module: {r['module']} | Target: {r['target']} | Date: {r['timestamp']}\n"
                sigma_bundle += y.strip() + "\n---\n\n"
                
        if extracted_count == 0:
            sigma_bundle += "# No Sigma rules found in current audit database logs."

        return Response(
            sigma_bundle,
            mimetype="application/x-yaml",
            headers={"Content-Disposition": "attachment;filename=ghost_sentinel_sigma_rules.yml"}
        )
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/logs', methods=['GET'])
def get_logs():
    try:
        with sqlite3.connect('security_audit.db') as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 20")
            rows = cursor.fetchall()
            logs = [dict(row) for row in rows]
        return jsonify({"status": "success", "logs": logs})
    except Exception as e:
        return jsonify({"status": "error", "logs": [], "message": str(e)})


@app.route('/api/warroom', methods=['POST'])
def war_room_query():
    if not gemini_client:
        return jsonify({"status": "error", "answer": "Gemini client not configured. Set GEMINI_API_KEY."})

    data = request.get_json() or {}
    user_query = data.get('query', '')
    
    try:
        with sqlite3.connect('security_audit.db') as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT timestamp, module, target, risk_score, ai_analysis FROM audit_logs ORDER BY id DESC LIMIT 15")
            rows = cursor.fetchall()
            log_context = "\n".join([
                f"[{r['timestamp']}] Module: {r['module']} | Target: {r['target']} | Score: {r['risk_score']} | Summary: {r['ai_analysis'][:200]}"
                for r in rows
            ])
    except Exception:
        log_context = "No audit logs available."

    prompt = (
        f"You are CyberBuddy, an AI security analyst reviewing Ghost-Aegis audit records.\n"
        f"Here are the recent audit logs from the database:\n{log_context}\n\n"
        f"User Question: {user_query}\n\n"
        "Provide a clear, tactical answer referencing the logs above."
    )

    try:
        chat = gemini_client.chats.create(model='gemini-3.6-flash')
        response = chat.send_message(prompt)
        return jsonify({"status": "success", "answer": response.text})
    except Exception as e:
        return jsonify({"status": "error", "answer": f"War Room AI error: {str(e)}"})


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)