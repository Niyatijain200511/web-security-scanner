# Automated Web Security Scanner

A Python command-line tool that audits websites for common security
misconfigurations and produces a graded HTML report.

## Features
- Checks 6 security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options,
  Referrer-Policy, Permissions-Policy)
- Detects version disclosure (Server, X-Powered-By)
- Audits cookie flags (Secure, HttpOnly, SameSite)
- Tests CORS misconfigurations (reflected origins, null origin, wildcard, credentials)
- Checks HTTP to HTTPS redirect
- Scores each site A-F and exports a color-coded HTML report with fix advice

## Installation
    python -m venv venv
    venv\Scripts\activate
    pip install requests

## Usage
    python scanner.py https://example.com
    python scanner.py https://example.com -o report.html
    python scanner.py -f urls.txt

## Testing
`vuln_server.py` is a deliberately insecure local server for validating
the scanner:
    python vuln_server.py
    python scanner.py http://127.0.0.1:5000

## Results
| Target | Grade | Score |
|---|---|---|
| Local vulnerable server | F | 0/100 |
| example.com | F | 33/100 |
| github.com | B | 89/100 |

## Scoring
Starts at 100. Deductions: CRITICAL -30, HIGH -15, MEDIUM -8, LOW -3.
A >= 90, B >= 75, C >= 60, D >= 40, F < 40.

## Limitations
- Passive checks only; no authenticated scanning
- Cannot tell sensitive cookies from analytics cookies (possible false positives)
- Scans a single page, not a full crawl
- A missing header may be intentional for some sites

## Mapping
OWASP Top 10 A05:2021 Security Misconfiguration; OWASP Secure Headers Project.

## Legal notice
Only scan systems you own or have permission to test.