from flask import Flask, render_template, jsonify, request
from celery import Celery
import time
import datetime
import subprocess
import hashlib
import os
import re
import threading
import sqlite3
import requests
from google import genai
from openai import OpenAI
from models import log_audit

# Initialize Flask and Celery
app = Flask(__name__)
celery = Celery(
    app.name,
    broker='redis://redis:6379/0',
    backend='redis://redis:6379/0'
)
celery.conf.update(
    result_backend='redis://redis:6379/0',
    broker_url='redis://redis:6379/0'
)

start_time = time.time()

# Initialize Dual-AI Clients
gemini_api_key = os.environ.get("GEMINI_API_KEY")
copilot_api_key = os.environ.get("COPILOT_API_KEY")

gemini_client = genai.Client(api_key=gemini_api_key) if gemini_api_key else None
copilot_client = OpenAI(api_key=copilot_api_key) if copilot_api_key else None


def evaluate_threat_level(module_name, output_text):
    # 1. Copilot Prompt (Ghost - Red Team Offensive Persona)
    ghost_prompt = (
        f"You are GHOST, an elite Red Team offensive security specialist. "
        f"Analyze this raw output from module '{module_name}':\n\n{output_text}\n\n"
        "Provide your analysis in this exact format:\n"
        "[SCORE: <0-100>]\n"
        "MITRE ATT&CK: [List relevant technique IDs like T1046, T1021]\n"
        "EXPLOIT PATH: <Concise explanation of how an attacker would exploit this target>\n"
    )

    # 2. Gemini Prompt (Aegis - Blue Team Defensive Persona)
    aegis_prompt = (
        f"You are AEGIS, a Tier-3 Blue Team Security Operations defender. "
        f"Analyze this raw output from module '{module_name}':\n\n{output_text}\n\n"
        "Provide your analysis in this exact format:\n"
        "[SCORE: <0-100>]\n"
        "DEFENSE POSTURE: <Telemetry analysis and blind spots>\n"
        "REMEDIATION SCRIPT:\n"
        "```bash\n"
        "# Copy-pasteable shell commands (iptables, systemctl, etc.) to harden this finding\n"
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

    # Execute Ghost (Copilot / OpenAI)
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

    # Execute Aegis (Gemini with auto-retry)
    if gemini_client:
        for model_name in ['gemini-3.5-flash', 'gemini-3.6-flash', 'gemini-3.7-flash']:
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
                if "503" in str(e):
                    time.sleep(1)
                    continue
                break

    # Calculate Consensus
    scores = [s for s in [ghost_score, aegis_score] if s is not None]
    consensus = int(sum(scores) / len(scores)) if scores else 0

    return (
        f"[SCORE: {consensus}]\n\n"
        f"🔴 === GHOST (RED TEAM EXPLOIT ANALYSIS) ===\n{ghost_result}\n\n"
        f"🔵 === AEGIS (BLUE TEAM DEFENSE & REMEDIATION) ===\n{aegis_result}"
    )



def dispatch_soar_alert(module, target, score, analysis):
    # Optional webhook URL (Discord, Slack, or local SIEM receiver)
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


@celery.task(name='app.run_fim_scan')
def run_fim_scan(directory='/app'):
    integrity_report = {}
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(('.py', '.sh', '.conf')):
                fullpath = os.path.join(root, file)
                integrity_report[fullpath] = calculate_sha256(fullpath)
    return integrity_report


def run_cmd(command_list):
    try:
        result = subprocess.run(command_list, capture_output=True, text=True, timeout=15)
        output = result.stdout + result.stderr
        return output if output.strip() else "Command executed with no output."
    except subprocess.TimeoutExpired:
        return "Error: Command timed out after 15 seconds."
    except Exception as e:
        return f"Execution error: {str(e)}"


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/telemetry')
def telemetry():
    uptime_seconds = int(time.time() - start_time)
    hours = uptime_seconds // 3600
    minutes = (uptime_seconds % 3600) // 60
    seconds = uptime_seconds % 60
    try:
        proc_count = len(subprocess.check_output(["ps", "aux"]).splitlines())
    except Exception:
        proc_count = 12
    return jsonify({
        "uptime": f"{hours}h {minutes}m {seconds}s",
        "active_processes": proc_count
    })


@app.route('/api/scan', methods=['POST'])
def scan():
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output = run_cmd(["ss", "-tuln"])
    ai_analysis = evaluate_threat_level("scan", output)
    match = re.search(r'\[SCORE:\s*(\d+)\]', ai_analysis)
    score = int(match.group(1)) if match else 0
    log_audit(current_time, "scan", "localhost", ai_analysis, score)
    return jsonify({"time": current_time, "result": ai_analysis, "risk_score": score})


@app.route('/api/discover', methods=['POST'])
def discover():
    data = request.get_json() or {}
    target = data.get('target', '192.168.1.0/24')
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output = run_cmd(["nmap", "-sn", target])
    ai_analysis = evaluate_threat_level("discover", output)
    match = re.search(r'\[SCORE:\s*(\d+)\]', ai_analysis)
    score = int(match.group(1)) if match else 0
    log_audit(current_time, "discover", target, ai_analysis, score)
    return jsonify({"time": current_time, "result": ai_analysis, "risk_score": score})


@app.route('/api/ports', methods=['POST'])
def ports():
    data = request.get_json() or {}
    target = data.get('target', 'localhost')
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output = run_cmd(["nmap", "-T4", "-F", target])
    ai_analysis = evaluate_threat_level("ports", output)
    match = re.search(r'\[SCORE:\s*(\d+)\]', ai_analysis)
    score = int(match.group(1)) if match else 0
    log_audit(current_time, "ports", target, ai_analysis, score)
    return jsonify({"time": current_time, "result": ai_analysis, "risk_score": score})


@app.route('/api/services', methods=['POST'])
def services():
    data = request.get_json() or {}
    target = data.get('target', 'localhost')
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output = run_cmd(["nmap", "-sV", "-p-", "--max-retries", "1", target])
    ai_analysis = evaluate_threat_level("services", output)
    match = re.search(r'\[SCORE:\s*(\d+)\]', ai_analysis)
    score = int(match.group(1)) if match else 0
    log_audit(current_time, "services", target, ai_analysis, score)
    return jsonify({"time": current_time, "result": ai_analysis, "risk_score": score})


@app.route('/api/dns', methods=['POST'])
def dns_lookup():
    data = request.get_json() or {}
    target = data.get('target', 'example.com')
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output = run_cmd(["dig", target])
    ai_analysis = evaluate_threat_level("dns", output)
    match = re.search(r'\[SCORE:\s*(\d+)\]', ai_analysis)
    score = int(match.group(1)) if match else 0
    log_audit(current_time, "dns", target, ai_analysis, score)
    return jsonify({"time": current_time, "result": ai_analysis, "risk_score": score})


@app.route('/api/whois', methods=['POST'])
def whois_lookup():
    data = request.get_json() or {}
    target = data.get('target', 'example.com')
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output = run_cmd(["whois", target])
    ai_analysis = evaluate_threat_level("whois", output)
    match = re.search(r'\[SCORE:\s*(\d+)\]', ai_analysis)
    score = int(match.group(1)) if match else 0
    log_audit(current_time, "whois", target, ai_analysis, score)
    return jsonify({"time": current_time, "result": ai_analysis, "risk_score": score})


@app.route('/api/traceroute', methods=['POST'])
def traceroute():
    data = request.get_json() or {}
    target = data.get('target', '8.8.8.8')
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output = run_cmd(["traceroute", "-m", "10", target])
    ai_analysis = evaluate_threat_level("traceroute", output)
    match = re.search(r'\[SCORE:\s*(\d+)\]', ai_analysis)
    score = int(match.group(1)) if match else 0
    log_audit(current_time, "traceroute", target, ai_analysis, score)
    return jsonify({"time": current_time, "result": ai_analysis, "risk_score": score})


@app.route('/api/web', methods=['POST'])
def web_scan():
    data = request.get_json() or {}
    target = data.get('target', 'localhost')
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output = run_cmd(["nikto", "-h", target])
    ai_analysis = evaluate_threat_level("web", output)
    match = re.search(r'\[SCORE:\s*(\d+)\]', ai_analysis)
    score = int(match.group(1)) if match else 0
    log_audit(current_time, "web", target, ai_analysis, score)
    return jsonify({"time": current_time, "result": ai_analysis, "risk_score": score})


@app.route('/api/ssl', methods=['POST'])
def ssl_scan():
    data = request.get_json() or {}
    target = data.get('target', 'localhost')
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    clean_target = target.replace("https://", "").replace("http://", "").split("/")[0]
    output = run_cmd(["openssl", "s_client", "-connect", f"{clean_target}:443", "-servername", clean_target])
    ai_analysis = evaluate_threat_level("ssl", output)
    match = re.search(r'\[SCORE:\s*(\d+)\]', ai_analysis)
    score = int(match.group(1)) if match else 0
    log_audit(current_time, "ssl", clean_target, ai_analysis, score)
    return jsonify({"time": current_time, "result": ai_analysis, "risk_score": score})


@app.route('/api/smb', methods=['POST'])
def smb_enum():
    data = request.get_json() or {}
    target = data.get('target', 'localhost')
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    output = run_cmd(["enum4linux", "-a", target])
    ai_analysis = evaluate_threat_level("smb", output)
    match = re.search(r'\[SCORE:\s*(\d+)\]', ai_analysis)
    score = int(match.group(1)) if match else 0
    log_audit(current_time, "smb", target, ai_analysis, score)
    return jsonify({"time": current_time, "result": ai_analysis, "risk_score": score})


def background_fim_scan(directory='/app'):
    integrity_report = {}
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(('.py', '.sh', '.conf')):
                fullpath = os.path.join(root, file)
                integrity_report[fullpath] = calculate_sha256(fullpath)
    log_audit(current_time, "fim", "local_filesystem", f"FIM scan completed across {len(integrity_report)} files.", 0)

@app.route('/api/fim', methods=['POST'])
def trigger_fim():
    try:
        integrity_report = {}
        for root, dirs, files in os.walk('/app'):
            for file in files:
                if file.endswith(('.py', '.sh', '.conf')):
                    fullpath = os.path.join(root, file)
                    integrity_report[fullpath] = calculate_sha256(fullpath)
        
        output_summary = f"File Integrity Monitor (FIM) Scan Complete. Tracked {len(integrity_report)} critical scripts:\n" + \
                         "\n".join([f"- {path}: `{digest[:16]}...`" for path, digest in list(integrity_report.items())[:15]])
        
        ai_analysis = evaluate_threat_level("fim", output_summary)
        match = re.search(r'\[SCORE:\s*(\d+)\]', ai_analysis)
        score = int(match.group(1)) if match else 0
        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_audit(current_time, "fim", "local_filesystem", ai_analysis, score)
        return jsonify({"time": current_time, "result": ai_analysis, "risk_score": score})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/logs', methods=['GET'])
def get_logs():
    try:
        conn = sqlite3.connect('security_audit.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 20")
        rows = cursor.fetchall()
        logs = [dict(row) for row in rows]
        conn.close()
        return jsonify({"status": "success", "logs": logs})
    except Exception as e:
        return jsonify({"status": "success", "logs": []})

@app.route('/api/warroom', methods=['POST'])
def war_room_query():
    data = request.get_json() or {}
    user_query = data.get('query', '')
    try:
        conn = sqlite3.connect('security_audit.db')
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("SELECT timestamp, module, target, risk_score, ai_analysis FROM audit_logs ORDER BY id DESC LIMIT 15")
        rows = cursor.fetchall()
        log_context = "\n".join([f"[{r['timestamp']}] Module: {r['module']} | Target: {r['target']} | Score: {r['risk_score']} | Summary: {r['ai_analysis'][:200]}" for r in rows])
        conn.close()
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