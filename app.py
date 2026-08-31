import datetime
import hashlib
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import time
from celery import Celery
from flask import Flask, jsonify, render_template, request
from google import genai
from openai import OpenAI

# Detect Host Operating System
IS_WINDOWS = platform.system().lower() == "windows"

# Initialize Flask and Celery
app = Flask(__name__)
redis_url = os.environ.get('REDIS_URL', 'redis://127.0.0.1:6379/0' if IS_WINDOWS else 'redis://redis:6379/0')
celery = Celery(app.name, broker=redis_url, backend=redis_url)
celery.conf.update(result_backend=redis_url, broker_url=redis_url)

start_time = time.time()

# Initialize AI Clients
gemini_api_key = os.environ.get("GEMINI_API_KEY")
copilot_api_key = os.environ.get("COPILOT_API_KEY")

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


def evaluate_threat_level(module_name, output_text):
    ghost_prompt = (
        f"Provide a threat assessment for the following scan output. "
        f"You are GHOST, an elite Red Team offensive security specialist. "
        f"Analyze this raw output from module '{module_name}':\n\n{output_text}\n\n"
        "Provide your analysis in this exact format:\n"
        "[SCORE: <0-100>]\n"
        "MITRE ATT&CK: [List relevant technique IDs like T1046, T1021]\n"
        "EXPLOIT PATH: <Concise explanation of how an attacker would exploit this target>\n"
    )

    aegis_prompt = (
        f"You are AEGIS, a Tier-3 Blue Team Security Operations defender. "
        f"Analyze this raw output from module '{module_name}':\n\n{output_text}\n\n"
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
        valid_models = ['gemini-3.6-flash', 'gemini-3.5-flash', 'gemini-3.0-flash']
        for model_name in valid_models:
            try:
                gemini_resp = gemini_client.models.generate_content(
                    model=model_name,
                    contents=aegis_prompt,
                )
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
        import requests
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
    # Check if executable exists in PATH
    if not shutil.which(executable):
        return f"Tool execution error: '{executable}' is not installed or not in system PATH on this host ({platform.system()})."

    try:
        result = subprocess.run(
            command_list,
            input=stdin_input,
            capture_output=True,
            text=True,
            timeout=15,
            shell=False
        )
        output = result.stdout + result.stderr
        return output if output.strip() else "Command executed with no output."
    except subprocess.TimeoutExpired:
        return "Error: Command timed out after 15 seconds."
    except Exception as e:
        return f"Execution error: {str(e)}"


def execute_pipeline(module, target, command_list, stdin_input=""):
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output = run_cmd(command_list, stdin_input=stdin_input)
    ai_analysis = evaluate_threat_level(module, output)
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
    return execute_pipeline("discover", target, ["nmap", "-sn", target])


@app.route('/api/ports', methods=['POST'])
def ports():
    data = request.get_json() or {}
    target = sanitize_target(data.get('target', 'localhost'))
    return execute_pipeline("ports", target, ["nmap", "-T4", "-F", target])


@app.route('/api/services', methods=['POST'])
def services():
    data = request.get_json() or {}
    target = sanitize_target(data.get('target', 'localhost'))
    return execute_pipeline("services", target, ["nmap", "-sV", "-p-", "--max-retries", "1", target])


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
    return execute_pipeline("whois", target, ["whois", target])


@app.route('/api/traceroute', methods=['POST'])
def traceroute():
    data = request.get_json() or {}
    target = sanitize_target(data.get('target', '8.8.8.8'))
    # Use tracert on Windows, traceroute on Linux
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
    try:
        base_dir = os.environ.get('SCAN_DIR', os.getcwd())
        integrity_report = {}
        for root, _, files in os.walk(base_dir):
            for file in files:
                if file.endswith(('.py', '.sh', '.bat', '.ps1', '.conf', '.json')):
                    fullpath = os.path.join(root, file)
                    integrity_report[fullpath] = calculate_sha256(fullpath)
        
        output_summary = (
            f"File Integrity Monitor (FIM) Complete. Host OS: {platform.system()}.\n"
            f"Tracked {len(integrity_report)} critical scripts in {base_dir}:\n" +
            "\n".join([f"- {path}: `{digest[:16]}...`" for path, digest in list(integrity_report.items())[:15]])
        )
        
        ai_analysis = evaluate_threat_level("fim", output_summary)
        match = re.search(r'\[SCORE:\s*(\d+)\]', ai_analysis)
        score = int(match.group(1)) if match else 0
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        log_audit(current_time, "fim", base_dir, ai_analysis, score)
        dispatch_soar_alert("fim", base_dir, score, ai_analysis)
        
        return jsonify({"time": current_time, "result": ai_analysis, "risk_score": score})
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
        response = gemini_client.models.generate_content(
            model='gemini-3.6-flash',
            contents=prompt, 
        )
        return jsonify({"status": "success", "answer": response.text})
    except Exception as e:
        return jsonify({"status": "error", "answer": f"War Room AI error: {str(e)}"})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)