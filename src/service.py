PROJECT_NAME = "Web Application Security Scanner"


from datetime import datetime
from urllib.parse import urlparse, parse_qs

SQL_TOKENS = ["'", "\"", " or ", " union ", "--", "/*", "sleep("]
XSS_TOKENS = ["<script", "javascript:", "onerror=", "onload="]
SECURITY_HEADERS = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Strict-Transport-Security"]

def analyze(payload):
    url = payload.get("url", "https://example.com")
    headers = payload.get("headers") or {}
    forms = payload.get("forms") or []
    parsed = urlparse(url)
    findings = []
    query = " ".join(parse_qs(parsed.query).keys()) + " " + parsed.query
    if any(token in query.lower() for token in SQL_TOKENS):
        findings.append({"type": "sql_injection", "severity": "high", "evidence": "Suspicious SQL metacharacters in URL query."})
    if any(token in query.lower() for token in XSS_TOKENS):
        findings.append({"type": "xss", "severity": "high", "evidence": "Suspicious script token in URL query."})
    for header in SECURITY_HEADERS:
        if header not in headers:
            findings.append({"type": "missing_header", "severity": "medium", "evidence": header + " is not present in supplied headers."})
    for form in forms:
        has_token = any("csrf" in str(key).lower() or "token" in str(key).lower() for key in form.keys())
        if not has_token:
            findings.append({"type": "csrf", "severity": "medium", "evidence": "Form lacks an obvious anti-CSRF token field."})
    return {
        "target": parsed.netloc or url,
        "findings": findings,
        "score": min(100, len([f for f in findings if f["severity"] == "high"]) * 35 + len(findings) * 10),
        "generated_at": datetime.utcnow().isoformat() + "Z"
    }

