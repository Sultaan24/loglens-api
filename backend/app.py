from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import check_password_hash
import re
import os
import uuid
import threading
import time
import requests
import json


app = Flask(__name__)
CORS(app)
import os
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(BASE_DIR, "signatures.json"), "r") as f:
    signatures = json.load(f)


jobs = {}
ADMIN_USER = "admin"
ADMIN_HASH = "scrypt:32768:8:1$evTJTBY8cP6WcaFX$46ab8f3cf959e508d3f45993a341598e2ff2e8029e1d7402dd7f9de0ee05245c8e706c00b7470d4d7c32d812620e769e4e1bed42bf96ecb5966c878297e47045"

# Apache/Nginx Common Log Format + Referrer + User Agent
pattern = r'(\d+\.\d+\.\d+\.\d+)\s-\s-\s\[(.*?)\]\s"(GET|POST)\s(.*?)\sHTTP/.*"\s(\d+)\s"(.*?)"\s"(.*?)"'

# ---------------------------
# Threat Detection
# ---------------------------
def detect_attack(path, status):
    path = path.lower()

    for sig in signatures:
        if sig["pattern"].lower() in path:
            return sig["type"], sig["severity"]

    if status == "401":
        return "brute_force", "low"

    return "normal", "none"









    # SQL Injection
    sql_patterns = [
        "union select",
        "' or 1=1",
        "or%201=1",
        "sleep(",
        "information_schema"
    ]
    if any(p in path for p in sql_patterns):
        return "sql_injection", "high"

    # XSS
    xss_patterns = [
        "<script>",
        "javascript:",
        "onerror=",
        "alert(",
        "%3cscript%3e"
    ]
    if any(p in path for p in xss_patterns):
        return "xss", "high"

    # Directory Traversal
    if "../" in path or "..%2f" in path or "/etc/passwd" in path:
        return "directory_traversal", "high"

    # Scanner / Bots
    bot_patterns = ["sqlmap", "nikto", "nmap", "acunetix", "scanner"]
    if any(b in user_agent for b in bot_patterns):
        return "security_scanner", "medium"

    # Brute Force
    if status == "401":
        return "brute_force", "low"

    # Suspicious Admin Access
    if "/admin" in path or "/wp-admin" in path:
        return "admin_probe", "medium"

    return "normal", "none"

# ---------------------------
# Country / Geo Mock
# ---------------------------

def get_country(ip):
    try:
        if ip.startswith("127.") or ip.startswith("192.168"):
            return "Local Network"

        url = f"http://ip-api.com/json/{ip}?fields=country"
        res = requests.get(url, timeout=2)
        data = res.json()

        return data.get("country", "Unknown")
    except:
        return "Unknown"








# ---------------------------
# Main Parser Function
# ---------------------------

def parse_lines(lines):
    results = []
    total_lines = 0
    skipped_lines = 0
    start_time = time.time()

    # Multiple log patterns
    patterns = [
        # Combined Log Format
        r'(\d+\.\d+\.\d+\.\d+)\s-\s-\s\[(.*?)\]\s"(\S+)\s(.*?)\sHTTP/.*"\s(\d+)\s(\d+)\s"(.*?)"\s"(.*?)"',

        # Common Log Format
        r'(\d+\.\d+\.\d+\.\d+)\s-\s-\s\[(.*?)\]\s"(\S+)\s(.*?)\sHTTP/.*"\s(\d+)\s(\d+)'
    ]

    for line in lines:
        total_lines += 1

        try:
            line = line.decode("utf-8", errors="ignore").strip()
        except:
            skipped_lines += 1
            continue

        if not line:
            skipped_lines += 1
            continue

        match = None

        for p in patterns:
            match = re.search(p, line)
            if match:
                break

        if match:
            try:
                ip = match.group(1)
                timestamp = match.group(2)
                method = match.group(3)
                path = match.group(4)
                status = match.group(5)

                # Combined format has referrer + user-agent
                if len(match.groups()) >= 8:
                    referrer = match.group(7)
                    user_agent = match.group(8)
                else:
                    referrer = "-"
                    user_agent = "-"

                attack, severity = detect_attack(path, status)
                country = get_country(ip)

                data = {
                    "ip": ip,
                    "timestamp": timestamp,
                    "method": method,
                    "path": path,
                    "status": status,
                    "referrer": referrer,
                    "user_agent": user_agent,
                    "attack": attack,
                    "severity": severity,
                    "country": country
                }

                results.append(data)

            except:
                skipped_lines += 1
        else:
            skipped_lines += 1

    ip_count = {}
    for r in results:
        if r["attack"] != "normal":
            ip_count[r["ip"]] = ip_count.get(r["ip"], 0) + 1

    total_attacks = len([x for x in results if x["attack"] != "normal"])

    return {
        "logs": results,
        "top_attackers": ip_count,
        "total_logs": len(results),
        "total_attacks": total_attacks,
        "total_lines": total_lines,
        "skipped_lines": skipped_lines,
        "processing_time": round(time.time() - start_time, 2)
    }













# ---------------------------
# Upload Route
# ---------------------------
def process_job(job_id, lines):
    jobs[job_id]["status"] = "processing"
    jobs[job_id]["progress"] = 10

    time.sleep(1)

    try:
        jobs[job_id]["progress"] = 40

        result = parse_lines(lines)

        jobs[job_id]["progress"] = 90
        time.sleep(1)

        jobs[job_id]["status"] = "completed"
        jobs[job_id]["progress"] = 100
        jobs[job_id]["result"] = result

    except Exception as e:
        jobs[job_id]["status"] = "failed"
        jobs[job_id]["error"] = str(e)

@app.route("/upload_async", methods=["POST"])
def upload_async():
    file = request.files["file"]
    lines = file.readlines()

    job_id = str(uuid.uuid4())

    jobs[job_id] = {
        "status": "queued",
        "progress": 0,
        "result": None
    }

    thread = threading.Thread(
        target=process_job,
        args=(job_id, lines)
    )
    thread.start()

    return jsonify({
        "job_id": job_id,
        "status": "queued"
    })


@app.route("/upload", methods=["POST"])
def upload_file():
    file = request.files["file"]

    def generate_lines():
        for line in file.stream:
            yield line

    result = parse_lines(generate_lines())
    return jsonify(result)






# ---------------------------
# Demo Route
# ---------------------------
@app.route("/demo", methods=["GET"])
def demo():
    demo_lines = [
        b'127.0.0.1 - - [10/Oct/2025:13:55:36] "GET /index.html HTTP/1.1" 200 "-" "Mozilla/5.0"',
        b'192.168.1.1 - - [10/Oct/2025:14:00:00] "POST /login HTTP/1.1" 401 "-" "Chrome/120.0"',
        b'192.168.1.5 - - [10/Oct/2025:14:10:00] "GET /index.php?id=1 UNION SELECT HTTP/1.1" 200 "-" "sqlmap/1.7"',
        b'8.8.8.8 - - [10/Oct/2025:15:10:00] "GET /../../etc/passwd HTTP/1.1" 403 "-" "Scanner"',
        b'45.33.22.11 - - [10/Oct/2025:16:00:00] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 "-" "Bot"',
    ]

    result = parse_lines(demo_lines)
    return jsonify(result)


# ---------------------------
# Home Route
# ---------------------------
@app.route("/")
def home():
    return "LogLens Backend Running 🚀"


# ---------------------------
# Run App
# ---------------------------
@app.route("/status/<job_id>", methods=["GET"])
def check_status(job_id):
    job = jobs.get(job_id)

    if not job:
        return jsonify({"error": "Job not found"}), 404

    return jsonify(job)


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    username = data.get("username")
    password = data.get("password")

    if username == ADMIN_USER and check_password_hash(ADMIN_HASH, password):
        return jsonify({
            "success": True,
            "message": "Login successful"
        })

    return jsonify({
        "success": False,
        "message": "Invalid credentials"
    }), 401










if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
