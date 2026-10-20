# Automated Web Application Security & Header Audit Scanner

**Author:** Joydip Maiti  
**Bootcamp:** IBM SkillsBuild Cyber Security BootCamp 2026 | BharatCares  
**Submission Requirement:** Complete Project Code (.py & .ipynb), Requirements (.txt), Project Report (.docx), and Documentation (.md)

---

## 🎯 1. Project Overview
This project delivers a modular, automated **Web Application Security Scanner** that audits websites against OWASP Top 10 security standards. It evaluates:
1. **Defensive HTTP Security Headers:** (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).
2. **CORS Vulnerabilities:** Tests for wildcard `*` with credentials and arbitrary origin reflection.
3. **Cookie Hardening:** Audits session tokens for `Secure`, `HttpOnly`, and `SameSite` flags.
4. **SSL/TLS Validation:** Inspects encryption ciphers, protocol versions, and certificate expiry.
5. **Information Disclosure:** Identifies leaking server banners and technology fingerprints (`X-Powered-By`).

---

## 🛠️ 2. Technologies Used
* **Programming Language:** Python 3.10+ / 3.14
* **Networking & HTTP:** `requests`, `urllib3`, `ssl`, `socket`
* **Reporting:** Modern CSS Glassmorphic HTML, JSON, and `python-docx`

---

## 🚀 3. Setup and Execution Instructions

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Audit Any Website / Domain
Run the script passing any target URL:
```bash
python Joydip_Maiti_Automated_Web_Security_Scanner.py https://example.com
```

### Step 3: View the Interactive HTML Report
Open the generated report in any browser:
```bash
# Windows
start reports/security_audit_report.html
```

### Step 4: Run via Jupyter Notebook
```bash
jupyter notebook Joydip_Maiti_Automated_Web_Security_Scanner.ipynb
```

---

## 📁 4. Directory & Submission Structure
```
Automated_Web_Security_Scanner/
├── Joydip_Maiti_Automated_Web_Security_Scanner.py      # Core Python scanner
├── Joydip_Maiti_Automated_Web_Security_Scanner.ipynb   # Interactive Jupyter Notebook
├── Joydip_Maiti_ProjectReport.docx                    # Comprehensive Word technical report
├── requirements.txt                                   # Dependencies list
├── README.md                                          # Detailed project overview
└── reports/                                           # Output audit reports
    ├── security_audit_report.html
    └── security_audit_report.json
```

---

## 🎓 5. Viva & Interview Questions Quick Guide
1. **Q: What is the risk of missing Content-Security-Policy (CSP)?**  
   *A:* Without CSP, attackers can inject and execute unauthorized malicious scripts (Cross-Site Scripting - XSS) in victims' browsers.
2. **Q: What happens if a cookie lacks the HttpOnly flag?**  
   *A:* Any JavaScript code running in the browser (e.g., via an XSS flaw) can read `document.cookie` and steal session tokens.
3. **Q: What is a CORS misconfiguration?**  
   *A:* When a server reflects arbitrary untrusted origins and allows credentials, malicious external websites can make authenticated API requests to steal private user data.