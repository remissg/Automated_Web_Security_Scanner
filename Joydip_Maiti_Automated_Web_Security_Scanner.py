"""
=============================================================================
IBM SkillsBuild Cyber Security BootCamp 2026 | BharatCares
Project Title: Automated Web Application Security & Header Audit Scanner
Author: Joydip Maiti
File: Joydip_Maiti_Automated_Web_Security_Scanner.py

Description:
A modular Python security scanner that audits web applications against OWASP
standards. It inspects HTTP security headers, CORS misconfigurations, cookie
flags (Secure, HttpOnly, SameSite), SSL/TLS certificates, and technology
fingerprints, producing both command-line and rich HTML/JSON audit reports.
=============================================================================
"""

import os
import sys
import json
import ssl
import socket
from datetime import datetime, timezone
import requests
from urllib.parse import urlparse

# Define required security headers and their defense rationale
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "name": "HTTP Strict Transport Security (HSTS)",
        "description": "Enforces encrypted HTTPS connections and mitigates SSL-stripping man-in-the-middle attacks.",
        "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "name": "Content Security Policy (CSP)",
        "description": "Restricts external resource loading and provides robust defense against Cross-Site Scripting (XSS).",
        "remediation": "Configure CSP header: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'"
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "name": "Clickjacking Defense (X-Frame-Options)",
        "description": "Prevents unauthorized framing of the web application inside hostile iframes.",
        "remediation": "Add header: X-Frame-Options: DENY or SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "name": "MIME Sniffing Protection (X-Content-Type-Options)",
        "description": "Prevents web browsers from MIME-sniffing a response away from the declared content-type.",
        "remediation": "Add header: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "name": "Referrer Policy",
        "description": "Protects private internal URL parameters from leaking to external referrers.",
        "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "name": "Browser Feature Permissions-Policy",
        "description": "Controls browser access to sensitive device APIs (camera, microphone, geolocation).",
        "remediation": "Add header: Permissions-Policy: geolocation=(), microphone=(), camera=()"
    }
}


class WebSecurityScanner:
    def __init__(self, target_url, output_dir="reports"):
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.domain = self.parsed_url.netloc
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

        self.findings = []
        self.passed_checks = []
        self.cookie_findings = []
        self.cors_findings = []
        self.ssl_info = {}
        self.tech_info = {}
        self.overall_score = 100

    def audit_headers(self, response):
        """Audit HTTP security headers and sensitive information disclosure."""
        print("[*] Auditing HTTP Response Security Headers...")
        headers = response.headers

        # Check for Information Leaks
        if "Server" in headers:
            val = headers["Server"]
            self.tech_info["Server"] = val
            if any(char.isdigit() for char in val):
                self.findings.append({
                    "category": "Information Disclosure",
                    "severity": "LOW",
                    "title": f"Server Banner Discloses Version ({val})",
                    "description": "The web server explicitly discloses its exact software version, facilitating targeted exploit research by threat actors.",
                    "remediation": "Suppress server tokens in your web server configuration (e.g., ServerTokens Prod in Apache, server_tokens off in Nginx)."
                })
                self.overall_score -= 5

        if "X-Powered-By" in headers:
            val = headers["X-Powered-By"]
            self.tech_info["X-Powered-By"] = val
            self.findings.append({
                "category": "Information Disclosure",
                "severity": "LOW",
                "title": f"Technology Stack Leaked via X-Powered-By ({val})",
                "description": "Underlying application frameworks are revealed to attackers.",
                "remediation": "Disable the X-Powered-By header in your application framework configuration."
            })
            self.overall_score -= 5

        # Audit Required Defensive Headers
        for header, meta in SECURITY_HEADERS.items():
            if header not in headers:
                deduction = 15 if meta["severity"] == "HIGH" else (10 if meta["severity"] == "MEDIUM" else 5)
                self.overall_score -= deduction
                self.findings.append({
                    "category": "Missing Security Header",
                    "severity": meta["severity"],
                    "title": f"Missing: {meta['name']}",
                    "description": meta["description"],
                    "remediation": meta["remediation"]
                })
            else:
                self.passed_checks.append({
                    "header": header,
                    "value": headers[header],
                    "name": meta["name"]
                })

    def audit_cors(self):
        """Audit Cross-Origin Resource Sharing (CORS) configurations."""
        print("[*] Testing for CORS Misconfigurations...")
        test_origin = "https://evil-attacker-website.com"
        headers = {"Origin": test_origin}

        try:
            res = requests.get(self.target_url, headers=headers, timeout=8, verify=False)
            aca_origin = res.headers.get("Access-Control-Allow-Origin")
            aca_credentials = res.headers.get("Access-Control-Allow-Credentials")

            if aca_origin:
                if aca_origin == "*" and aca_credentials == "true":
                    self.findings.append({
                        "category": "CORS Vulnerability",
                        "severity": "CRITICAL",
                        "title": "CORS Wildcard with Credentials Allowed",
                        "description": "The application allows arbitrary origins to make credentialed requests, leading to session hijacking.",
                        "remediation": "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true."
                    })
                    self.overall_score -= 25
                elif aca_origin == test_origin:
                    self.findings.append({
                        "category": "CORS Vulnerability",
                        "severity": "HIGH",
                        "title": "CORS Arbitrary Origin Reflection",
                        "description": "The application reflects untrusted Origin headers dynamically without whitelisting, exposing private user data to cross-domain attacks.",
                        "remediation": "Enforce a strict server-side whitelist of authorized frontend domains."
                    })
                    self.overall_score -= 20
                else:
                    self.cors_findings.append(f"CORS Origin configured to: {aca_origin}")
            else:
                self.cors_findings.append("No unrestricted CORS headers detected (Safe Default).")
        except Exception as e:
            self.cors_findings.append(f"CORS verification note: {str(e)}")

    def audit_cookies(self, response):
        """Audit session cookies for Secure, HttpOnly, and SameSite attributes."""
        print("[*] Auditing Cookie Security Flags...")
        cookies = response.cookies

        if not cookies:
            self.cookie_findings.append("No HTTP cookies set by endpoint during initial response.")
            return

        for cookie in cookies:
            issues = []
            if not cookie.secure:
                issues.append("Missing 'Secure' flag (transmissible over cleartext HTTP)")
                self.overall_score -= 10
            if not cookie.has_nonstandard_attr("httponly") and not cookie._rest.get("httponly"):
                issues.append("Missing 'HttpOnly' flag (accessible via client-side JavaScript / XSS)")
                self.overall_score -= 10
            samesite = cookie._rest.get("samesite", "None")
            if samesite.lower() in ["none", ""]:
                issues.append("SameSite attribute is None or unset (vulnerable to CSRF)")
                self.overall_score -= 5

            if issues:
                self.findings.append({
                    "category": "Cookie Misconfiguration",
                    "severity": "MEDIUM",
                    "title": f"Insecure Cookie Flag: '{cookie.name}'",
                    "description": f"The cookie '{cookie.name}' lacks essential hardening flags: {', '.join(issues)}.",
                    "remediation": "Set Set-Cookie attributes: Secure; HttpOnly; SameSite=Lax (or Strict)."
                })

    def audit_ssl(self):
        """Examine SSL/TLS Certificate validity, cipher suite, and expiry."""
        print("[*] Validating SSL/TLS Certificate & Handshake...")
        if self.parsed_url.scheme != "https":
            self.findings.append({
                "category": "Transport Layer Security",
                "severity": "CRITICAL",
                "title": "Insecure Cleartext Protocol (HTTP)",
                "description": "The target website is operating over cleartext HTTP without encryption.",
                "remediation": "Enforce TLS 1.2/1.3 across the entire web application and configure automated HTTPS redirection."
            })
            self.overall_score -= 30
            return

        try:
            port = self.parsed_url.port or 443
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, port), timeout=6) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    proto = ssock.version()

                    # Extract Expiry
                    exp_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (exp_date - datetime.now(timezone.utc)).days

                    self.ssl_info = {
                        "subject": dict(x[0] for x in cert['subject']),
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "expires": cert['notAfter'],
                        "days_left": days_left,
                        "cipher": cipher[0],
                        "protocol": proto
                    }

                    if days_left < 15:
                        self.findings.append({
                            "category": "SSL/TLS Security",
                            "severity": "HIGH",
                            "title": f"SSL Certificate Expiring Soon ({days_left} days left)",
                            "description": "The TLS certificate will expire imminently, which will cause widespread browser security warnings.",
                            "remediation": "Renew and rebind the SSL certificate through your Certificate Authority (CA) or Let's Encrypt."
                        })
                        self.overall_score -= 15
        except Exception as e:
            self.ssl_info["error"] = str(e)
            self.findings.append({
                "category": "SSL/TLS Security",
                "severity": "HIGH",
                "title": "SSL/TLS Handshake Anomaly",
                "description": f"Encountered TLS validation warning: {str(e)}",
                "remediation": "Verify SSL certificate trust chain and intermediate certificates."
            })
            self.overall_score -= 15

    def calculate_grade(self):
        """Compute an academic letter grade based on security score."""
        self.overall_score = max(0, min(100, self.overall_score))
        if self.overall_score >= 90:
            return "A", "#2ecc71"
        elif self.overall_score >= 80:
            return "B", "#3498db"
        elif self.overall_score >= 70:
            return "C", "#f39c12"
        elif self.overall_score >= 55:
            return "D", "#e67e22"
        else:
            return "F", "#e74c3c"

    def scan(self):
        """Execute full automated security audit."""
        print(f"\n=======================================================")
        print(f"[*] Starting Security Audit for: {self.target_url}")
        print(f"[*] Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"=======================================================\n")

        # Suppress insecure SSL warnings for testing
        requests.packages.urllib3.disable_warnings()

        try:
            response = requests.get(
                self.target_url,
                timeout=10,
                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) IBM-SkillsBuild-Auditor/2.0"},
                verify=False
            )
        except Exception as e:
            print(f"[-] Connection failed: {str(e)}")
            return False

        self.audit_headers(response)
        self.audit_cors()
        self.audit_cookies(response)
        self.audit_ssl()

        grade, grade_color = self.calculate_grade()
        self.print_terminal_summary(grade)
        self.generate_html_report(grade, grade_color)
        self.generate_json_report(grade)
        return True

    def print_terminal_summary(self, grade):
        """Output structured findings to terminal."""
        print("\n" + "=" * 65)
        print("                SECURITY AUDIT SUMMARY                ")
        print("=" * 65)
        print(f" Target URL:        {self.target_url}")
        print(f" Security Score:    {self.overall_score} / 100")
        print(f" Security Rating:   GRADE [{grade}]")
        print(f" Total Vulnerabilities Found: {len(self.findings)}")
        print(f" Defensive Headers Active:    {len(self.passed_checks)}")
        print("-" * 65)

        for i, f in enumerate(self.findings, 1):
            sev = f['severity']
            print(f" [{sev}] {i}. {f['title']}")
            print(f"        Category:    {f['category']}")
            print(f"        Remediation: {f['remediation']}")
            print()

        print("=" * 65 + "\n")

    def generate_html_report(self, grade, grade_color):
        """Create a professional modern HTML security report."""
        report_path = os.path.join(self.output_dir, "security_audit_report.html")

        findings_html = ""
        for f in self.findings:
            sev_badge = {
                "CRITICAL": "background:#e74c3c; color:white;",
                "HIGH": "background:#e67e22; color:white;",
                "MEDIUM": "background:#f1c40f; color:#2c3e50;",
                "LOW": "background:#3498db; color:white;"
            }.get(f['severity'], "background:#95a5a6; color:white;")

            findings_html += f"""
            <div class="finding-card">
                <div class="finding-header">
                    <span class="severity-badge" style="{sev_badge}">{f['severity']}</span>
                    <span class="finding-title">{f['title']}</span>
                </div>
                <div class="finding-body">
                    <p><strong>Category:</strong> {f['category']}</p>
                    <p><strong>Impact:</strong> {f['description']}</p>
                    <div class="remediation-box">
                        <strong>Recommended Remediation:</strong><br>
                        <code>{f['remediation']}</code>
                    </div>
                </div>
            </div>
            """

        passed_html = ""
        for p in self.passed_checks:
            passed_html += f"""
            <div class="passed-row">
                <span class="check-icon">✓</span>
                <strong>{p['header']}:</strong> <span class="header-val">{p['value'][:65]}...</span>
            </div>
            """

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Web Security Audit Report | Joydip Maiti</title>
    <style>
        :root {{
            --primary: #102C57;
            --accent: #2980b9;
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --text: #1e293b;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg);
            color: var(--text);
            margin: 0;
            padding: 30px;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
        }}
        .header {{
            background: linear-gradient(135deg, #102C57 0%, #1679AB 100%);
            color: white;
            padding: 30px;
            border-radius: 12px;
            box-shadow: 0 8px 24px rgba(0,0,0,0.1);
            margin-bottom: 25px;
        }}
        .header h1 {{ margin: 0 0 10px 0; font-size: 26px; }}
        .header p {{ margin: 4px 0; opacity: 0.9; }}
        .score-panel {{
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }}
        .score-card {{
            background: var(--card-bg);
            padding: 24px;
            border-radius: 12px;
            text-align: center;
            box-shadow: 0 4px 12px rgba(0,0,0,0.05);
            border: 1px solid #e2e8f0;
        }}
        .score-num {{
            font-size: 42px;
            font-weight: 800;
            margin: 10px 0;
        }}
        .finding-card {{
            background: var(--card-bg);
            border-radius: 10px;
            margin-bottom: 16px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.04);
            border: 1px solid #e2e8f0;
            overflow: hidden;
        }}
        .finding-header {{
            padding: 14px 20px;
            background: #f1f5f9;
            display: flex;
            align-items: center;
            gap: 12px;
        }}
        .severity-badge {{
            padding: 4px 10px;
            border-radius: 6px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.5px;
        }}
        .finding-title {{
            font-weight: 700;
            font-size: 15px;
        }}
        .finding-body {{
            padding: 18px 20px;
        }}
        .remediation-box {{
            background: #f8fafc;
            border-left: 4px solid var(--accent);
            padding: 12px 16px;
            margin-top: 12px;
            border-radius: 0 6px 6px 0;
        }}
        code {{
            background: #edf2f7;
            padding: 2px 6px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 13px;
        }}
        .passed-row {{
            padding: 10px 14px;
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            border-radius: 6px;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .check-icon {{
            color: #16a34a;
            font-weight: bold;
        }}
        .header-val {{
            color: #4b5563;
            font-family: monospace;
            font-size: 12px;
        }}
        footer {{
            text-align: center;
            margin-top: 40px;
            font-size: 13px;
            color: #64748b;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>IBM SkillsBuild Cyber Security 2026 | BharatCares</h1>
            <h2>Automated Web Security & Header Audit Report</h2>
            <p><strong>Target URL:</strong> {self.target_url}</p>
            <p><strong>Auditor:</strong> Joydip Maiti | Track: Application Security & Pentesting</p>
            <p><strong>Audit Date:</strong> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        </div>

        <div class="score-panel">
            <div class="score-card">
                <div>Security Posture Grade</div>
                <div class="score-num" style="color:{grade_color}">{grade}</div>
                <div>Industry Benchmark: Grade A</div>
            </div>
            <div class="score-card">
                <div>Numerical Security Score</div>
                <div class="score-num" style="color:var(--primary)">{self.overall_score}<span style="font-size:20px">/100</span></div>
                <div>Based on OWASP Standards</div>
            </div>
            <div class="score-card">
                <div>Vulnerabilities Identified</div>
                <div class="score-num" style="color:#e74c3c">{len(self.findings)}</div>
                <div>Requires System Hardening</div>
            </div>
        </div>

        <h3>🚨 Vulnerability Findings & Remediation Plan</h3>
        {findings_html if findings_html else '<p style="color:#16a34a">✓ No high-severity security vulnerabilities detected!</p>'}

        <h3 style="margin-top:35px">🛡️ Implemented Security Controls</h3>
        {passed_html if passed_html else '<p>No defensive HTTP security headers were identified.</p>'}

        <footer>
            Generated by <strong>Joydip Maiti's Automated Web Security Scanner</strong> | IBM SkillsBuild Cyber Security BootCamp 2026
        </footer>
    </div>
</body>
</html>
"""
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(html_template)
        print(f"[+] Saved rich HTML audit report to: {report_path}")

    def generate_json_report(self, grade):
        """Export machine-readable JSON summary for CI/CD integration."""
        json_path = os.path.join(self.output_dir, "security_audit_report.json")
        data = {
            "meta": {
                "author": "Joydip Maiti",
                "bootcamp": "IBM SkillsBuild Cyber Security 2026 | BharatCares",
                "scan_time_utc": datetime.now(timezone.utc).isoformat(),
                "target_url": self.target_url
            },
            "summary": {
                "grade": grade,
                "score": self.overall_score,
                "total_findings": len(self.findings),
                "passed_headers": len(self.passed_checks)
            },
            "ssl_info": self.ssl_info,
            "tech_info": self.tech_info,
            "findings": self.findings,
            "passed_checks": self.passed_checks
        }
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"[+] Saved machine-readable JSON report to: {json_path}")


def main():
    print("=" * 65)
    print(" IBM SkillsBuild Cyber Security 2026 | BharatCares ")
    print(" Automated Web Security & Vulnerability Header Scanner ")
    print(" Developer: Joydip Maiti")
    print("=" * 65)

    # Test on a real domain or standard target
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    scanner = WebSecurityScanner(
        target_url=target,
        output_dir=os.path.join(os.path.dirname(__file__), "reports")
    )
    scanner.scan()


if __name__ == "__main__":
    main()
