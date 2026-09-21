from flask import Flask, render_template, request, jsonify
import re
from datetime import datetime

app = Flask(__name__)
MAX_INPUT = 12000

PATTERNS = [
    ("Critical", r"(?i)api[_-]?key\s*=", "Possible hard-coded API key", "Move the key to an environment variable."),
    ("Critical", r"(?i)secret[_-]?key\s*=", "Possible hard-coded secret key", "Move the secret to an environment variable."),
    ("Critical", r"(?i)\b(password|passwd)\s*=", "Possible hard-coded password", "Do not hard-code passwords; use secure configuration."),
    ("High", r"(?i)\beval\s*\(", "Dangerous dynamic code execution", "Avoid eval() on untrusted input."),
    ("High", r"(?i)\bexec\s*\(", "Dangerous dynamic code execution", "Avoid exec() on untrusted input."),
    ("High", r"(?i)(SELECT.+FROM|INSERT\s+INTO|UPDATE.+SET|DELETE\s+FROM).*(\+|%s|format\s*\()", "Possible SQL injection pattern", "Use parameterized queries."),
    ("High", r"(?i)(os\.system|subprocess\.(run|Popen|call))", "OS command execution detected", "Validate input and avoid untrusted shell commands."),
    ("Medium", r"(?i)http://(?:localhost|127\.0\.0\.1)", "Unencrypted/local HTTP URL", "Prefer HTTPS for production URLs."),
    ("Medium", r"(?i)\bverify\s*=\s*False\b", "TLS verification disabled", "Keep certificate verification enabled."),
    ("Medium", r"(?i)\bdebug\s*=\s*True\b", "Debug mode enabled", "Disable debug mode in production."),
    ("Low", r"(?i)print\s*\(.*(?:password|token|secret|api[_-]?key)", "Possible secret leakage in logs", "Remove secrets from logs."),
]

def scan_code(code):
    findings = []
    for severity, pattern, title, fix in PATTERNS:
        for match in re.finditer(pattern, code):
            findings.append({
                "severity": severity,
                "title": title,
                "line": code.count("\n", 0, match.start()) + 1,
                "fix": fix
            })
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    return sorted(findings, key=lambda x: (order[x["severity"]], x["line"]))

def analyze_problem(problem):
    text = problem.strip()
    if not text:
        return {
            "status": "error",
            "message": "Please describe a problem first."
        }

    lower = text.lower()
    suggestions = []

    if any(x in lower for x in ["error", "exception", "traceback", "crash"]):
        suggestions.append("Read the exact error message and identify the file and line where it occurs.")
    if any(x in lower for x in ["json", "api", "fetch", "http", "vercel"]):
        suggestions.append("Check the API response status and make sure the frontend expects the same response format as the backend.")
    if any(x in lower for x in ["login", "password", "security", "key", "token"]):
        suggestions.append("Avoid exposing passwords, tokens, API keys, or other secrets in client-side code.")
    if any(x in lower for x in ["database", "sql", "query"]):
        suggestions.append("Use parameterized database queries instead of building SQL with string concatenation.")
    if not suggestions:
        suggestions = [
            "Break the problem into smaller steps.",
            "Check the console/server logs for the first error.",
            "Test the smallest reproducible case before changing multiple files."
        ]

    return {
        "status": "success",
        "problem": text,
        "suggestions": suggestions,
        "analyzed_at": datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    }

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def api_scan():
    try:
        data = request.get_json(silent=True) or {}
        code = data.get("code", "")
        if not isinstance(code, str):
            return jsonify({"status": "error", "message": "code must be text"}), 400
        if len(code) > MAX_INPUT:
            return jsonify({"status": "error", "message": f"Maximum {MAX_INPUT} characters allowed."}), 413

        findings = scan_code(code)
        return jsonify({
            "status": "success",
            "findings": findings,
            "count": len(findings),
            "scanned_at": datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        })
    except Exception:
        return jsonify({"status": "error", "message": "Unable to scan the submitted code."}), 500

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    try:
        data = request.get_json(silent=True) or {}
        problem = data.get("problem", "")
        if not isinstance(problem, str):
            return jsonify({"status": "error", "message": "problem must be text"}), 400
        if len(problem) > MAX_INPUT:
            return jsonify({"status": "error", "message": f"Maximum {MAX_INPUT} characters allowed."}), 413
        result = analyze_problem(problem)
        return jsonify(result), 200 if result["status"] == "success" else 400
    except Exception:
        return jsonify({"status": "error", "message": "Unable to analyze the problem."}), 500

@app.errorhandler(404)
def not_found(error):
    if request.path.startswith("/api/"):
        return jsonify({"status": "error", "message": "API endpoint not found."}), 404
    return render_template("index.html"), 404

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
