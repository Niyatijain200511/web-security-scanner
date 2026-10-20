# Automated Web Security Scanner
# This program checks a website for common security problems:
#   1. Missing security headers
#   2. Insecure cookies
#   3. CORS misconfiguration
#   4. No redirect from HTTP to HTTPS
# It gives the website a grade (A to F) and saves an HTML report.
#
# NOTE: Only scan websites that you own or have permission to test.

import requests
import argparse
import html
import sys
from datetime import datetime

# Name shown to the website when we send requests
HEADERS_TO_SEND = {"User-Agent": "SecScanner/1.0 (student project)"}

# Security headers we want to see in the website response.
# Format: (header name, severity, why it matters, how to fix)
SECURITY_HEADERS = [
    ("Strict-Transport-Security", "HIGH",
     "Forces browsers to use HTTPS",
     "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("Content-Security-Policy", "HIGH",
     "Helps stop XSS and injection attacks",
     "Add a CSP header, e.g. Content-Security-Policy: default-src 'self'"),
    ("X-Frame-Options", "MEDIUM",
     "Prevents clickjacking",
     "Add: X-Frame-Options: DENY"),
    ("X-Content-Type-Options", "MEDIUM",
     "Stops MIME type sniffing",
     "Add: X-Content-Type-Options: nosniff"),
    ("Referrer-Policy", "LOW",
     "Limits referrer data leakage",
     "Add: Referrer-Policy: strict-origin-when-cross-origin"),
    ("Permissions-Policy", "LOW",
     "Restricts browser features like camera and location",
     "Add: Permissions-Policy: geolocation=(), camera=()"),
]

# Points removed from the score for each finding
PENALTY = {"CRITICAL": 30, "HIGH": 15, "MEDIUM": 8, "LOW": 3}

# Colours used in the HTML report
COLORS = {"CRITICAL": "#b71c1c", "HIGH": "#e65100",
          "MEDIUM": "#f9a825", "LOW": "#1565c0"}


def make_finding(issue, severity, why, fix):
    # Store one problem as a dictionary
    return {"issue": issue, "severity": severity, "why": why, "fix": fix}


def check_headers(response):
    # Check if important security headers are missing
    findings = []

    for name, severity, why, fix in SECURITY_HEADERS:
        if name not in response.headers:
            findings.append(make_finding("Missing header: " + name,
                                         severity, why, fix))

    # Headers that reveal the software version are also a problem
    for name in ["Server", "X-Powered-By"]:
        value = response.headers.get(name)
        if value is not None:
            # if the value contains a number, it probably shows a version
            has_number = any(ch.isdigit() for ch in value)
            if has_number:
                findings.append(make_finding(
                    "Version disclosure: " + name + ": " + value,
                    "LOW",
                    "Shows software version to attackers",
                    "Remove or hide the " + name + " header"))
    return findings


def check_cookies(response, url):
    # Check cookie flags: Secure, HttpOnly, SameSite
    findings = []

    # Get all Set-Cookie headers (a site can set many cookies)
    try:
        cookies = response.raw.headers.getlist("Set-Cookie")
    except Exception:
        one_cookie = response.headers.get("Set-Cookie")
        cookies = [one_cookie] if one_cookie else []

    for cookie in cookies:
        cookie_name = cookie.split("=")[0].strip()
        cookie_lower = cookie.lower()

        # Secure flag only matters when the site uses HTTPS
        if url.startswith("https://") and "secure" not in cookie_lower:
            findings.append(make_finding(
                "Cookie '" + cookie_name + "' missing Secure flag",
                "MEDIUM",
                "Cookie can be sent over unencrypted HTTP",
                "Add the Secure attribute"))

        if "httponly" not in cookie_lower:
            findings.append(make_finding(
                "Cookie '" + cookie_name + "' missing HttpOnly flag",
                "MEDIUM",
                "JavaScript can read this cookie (XSS risk)",
                "Add the HttpOnly attribute"))

        if "samesite" not in cookie_lower:
            findings.append(make_finding(
                "Cookie '" + cookie_name + "' missing SameSite flag",
                "LOW",
                "Cookie can be sent from other sites (CSRF risk)",
                "Add SameSite=Lax or SameSite=Strict"))
    return findings


def check_cors(url):
    # CORS test: send a fake Origin header and see how the server reacts
    findings = []
    fake_origins = ["https://evil.com", "null"]

    for origin in fake_origins:
        try:
            headers = {"User-Agent": "SecScanner/1.0", "Origin": origin}
            response = requests.get(url, headers=headers, timeout=10)
        except requests.RequestException:
            continue

        allow_origin = response.headers.get("Access-Control-Allow-Origin")
        allow_creds = response.headers.get("Access-Control-Allow-Credentials", "")

        if allow_origin == origin and allow_creds.lower() == "true":
            # Worst case: any site can read logged-in data
            findings.append(make_finding(
                "CORS reflects origin '" + origin + "' WITH credentials",
                "CRITICAL",
                "Any website can make logged-in requests and read the response",
                "Use an allowlist of trusted origins, never copy the Origin header"))
        elif allow_origin == origin:
            findings.append(make_finding(
                "CORS reflects arbitrary origin '" + origin + "'",
                "HIGH",
                "Untrusted websites can read responses",
                "Use an allowlist of trusted origins"))
        elif allow_origin == "*":
            findings.append(make_finding(
                "CORS wildcard (Access-Control-Allow-Origin: *)",
                "MEDIUM",
                "Any website can read public responses",
                "Allow only specific trusted origins"))
            break  # no need to test the second origin again
    return findings


def check_https_redirect(url):
    # Check if http:// automatically redirects to https://
    findings = []
    host = url.split("//")[1].split("/")[0]  # get domain name only
    http_url = "http://" + host

    try:
        response = requests.get(http_url, headers=HEADERS_TO_SEND,
                                timeout=10, allow_redirects=False)
        location = response.headers.get("Location", "")
        is_redirect = 300 <= response.status_code < 400
        if not (is_redirect and location.startswith("https://")):
            findings.append(make_finding(
                "HTTP does not redirect to HTTPS",
                "HIGH",
                "Users can connect without encryption",
                "Redirect all HTTP traffic to HTTPS (301 redirect)"))
    except requests.RequestException:
        pass  # if the HTTP site is unreachable, we skip this check
    return findings


def calculate_grade(findings):
    # Start from 100 and remove points for every finding
    score = 100
    for f in findings:
        score = score - PENALTY[f["severity"]]
    if score < 0:
        score = 0

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    return score, grade


def scan_website(url):
    # Run all checks on one website
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    print("[*] Scanning " + url)

    try:
        response = requests.get(url, headers=HEADERS_TO_SEND,
                                timeout=10, allow_redirects=True)
    except requests.RequestException as error:
        print("[!] Could not reach " + url + ": " + str(error))
        return None

    findings = []
    findings = findings + check_headers(response)
    findings = findings + check_cookies(response, url)
    findings = findings + check_cors(url)
    findings = findings + check_https_redirect(url)

    score, grade = calculate_grade(findings)
    return {"url": url, "findings": findings, "score": score, "grade": grade}


def sort_by_severity(findings):
    # Most serious problems first
    return sorted(findings, key=lambda f: PENALTY[f["severity"]], reverse=True)


def print_result(result):
    # Show the result in the terminal
    print("\n=== " + result["url"] + " ===")
    print("Grade: " + result["grade"] + "   Score: " + str(result["score"])
          + "/100   Findings: " + str(len(result["findings"])))
    for f in sort_by_severity(result["findings"]):
        print("  [" + f["severity"] + "] " + f["issue"])
    print()


def save_html_report(results, filename):
    # Build the HTML report as a string and save it to a file
    page = "<html><head><meta charset='utf-8'><title>Security Scan Report</title>"
    page += "<style>"
    page += "body{font-family:Arial;margin:30px;background:#fafafa}"
    page += "table{border-collapse:collapse;width:100%;margin-bottom:30px}"
    page += "th,td{border:1px solid #ddd;padding:8px;text-align:left;vertical-align:top}"
    page += "th{background:#263238;color:white}"
    page += ".grade{font-size:48px;font-weight:bold}"
    page += ".sev{color:white;padding:2px 8px;border-radius:4px;font-size:12px}"
    page += "</style></head><body>"
    page += "<h1>Web Security Scan Report</h1>"
    page += "<p>Generated " + datetime.now().strftime("%Y-%m-%d %H:%M") + "</p>"

    for result in results:
        page += "<h2>" + html.escape(result["url"]) + "</h2>"
        page += "<div class='grade'>Grade " + result["grade"]
        page += " (" + str(result["score"]) + "/100)</div>"
        page += "<table><tr><th>Severity</th><th>Issue</th>"
        page += "<th>Why it matters</th><th>How to fix</th></tr>"

        for f in sort_by_severity(result["findings"]):
            color = COLORS[f["severity"]]
            page += "<tr>"
            page += "<td><span class='sev' style='background:" + color + "'>"
            page += f["severity"] + "</span></td>"
            page += "<td>" + html.escape(f["issue"]) + "</td>"
            page += "<td>" + html.escape(f["why"]) + "</td>"
            page += "<td>" + html.escape(f["fix"]) + "</td>"
            page += "</tr>"

        if len(result["findings"]) == 0:
            page += "<tr><td colspan='4'>No issues found.</td></tr>"
        page += "</table>"

    page += "</body></html>"

    with open(filename, "w", encoding="utf-8") as file:
        file.write(page)
    print("[+] HTML report saved to " + filename)


def main():
    # Read command line arguments
    parser = argparse.ArgumentParser(description="Web security scanner")
    parser.add_argument("url", nargs="?", help="website to scan")
    parser.add_argument("-f", "--file", help="text file with one URL per line")
    parser.add_argument("-o", "--output", default="report.html",
                        help="name of the HTML report file")
    args = parser.parse_args()

    # Collect all websites to scan
    targets = []
    if args.url:
        targets.append(args.url)
    if args.file:
        with open(args.file) as file:
            for line in file:
                line = line.strip()
                if line:
                    targets.append(line)

    if len(targets) == 0:
        parser.print_help()
        sys.exit(1)

    # Scan each website
    results = []
    for target in targets:
        result = scan_website(target)
        if result is not None:
            results.append(result)

    for result in results:
        print_result(result)

    if len(results) > 0:
        save_html_report(results, args.output)


if __name__ == "__main__":
    main()