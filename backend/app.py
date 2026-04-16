from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import os

app = Flask(__name__)
CORS(app)

# Apache/Nginx Common Log Format + Referrer + User Agent
pattern = r'(\d+\.\d+\.\d+\.\d+)\s-\s-\s\[(.*?)\]\s"(GET|POST)\s(.*?)\sHTTP/.*"\s(\d+)\s"(.*?)"\s"(.*?)"'

# ---------------------------
# Threat Detection
# ---------------------------
def detect_attack(path, status):
    path = path.lower()

    if "union select" in path or "' or 1=1" in path:
        return "sql_injection", "high"

    elif "<script>" in path or "javascript:" in path:
        return "xss", "medium"

    elif "../" in path:
        return "directory_traversal", "high"

    elif status == "401":
        return "brute_force", "low"

    else:
        return "normal", "none"


# ---------------------------
# Country / Geo Mock
# ---------------------------
def get_country(ip):
    if ip.startswith("192.168"):
        return "India"
    elif ip.startswith("8.8"):
        return "United States"
    elif ip.startswith("45."):
        return "Germany"
    elif ip.startswith("127."):
        return "Localhost"
    else:
        return "Unknown"


# ---------------------------
# Main Parser Function
# ---------------------------
def parse_lines(lines):
    results = []

    for line in lines:
        line = line.decode("utf-8").strip()
        match = re.search(pattern, line)

        if match:
            ip = match.group(1)
            timestamp = match.group(2)
            method = match.group(3)
            path = match.group(4)
            status = match.group(5)
            referrer = match.group(6)
            user_agent = match.group(7)

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

    # Count attackers
    ip_count = {}
    for r in results:
        if r["attack"] != "normal":
            ip_count[r["ip"]] = ip_count.get(r["ip"], 0) + 1

    total_attacks = len([x for x in results if x["attack"] != "normal"])

    return {
        "logs": results,
        "top_attackers": ip_count,
        "total_logs": len(results),
        "total_attacks": total_attacks
    }


# ---------------------------
# Upload Route
# ---------------------------
@app.route("/upload", methods=["POST"])
def upload_file():
    file = request.files["file"]
    lines = file.readlines()
    result = parse_lines(lines)
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
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
