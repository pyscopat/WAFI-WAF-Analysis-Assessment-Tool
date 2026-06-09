# WAFI-WAF-Analysis-Assessment-Tool
This tool is intended for authorized security testing only. Use WAFI exclusively on systems you own or have explicit written permission to test. Unauthorized use against systems without permission is illegal and unethical. The author assumes no liability for misuse of this tool

# WAFI — WAF Analysis & Bypass Assessment Tool

> A Python-based penetration testing toolkit to detect, fingerprint, and assess Web Application Firewall (WAF) bypass scenarios during authorized security engagements.

---

## Overview

WAFI automates the process of identifying WAF presence and testing bypass techniques against web application endpoints. It combines WAF fingerprinting, payload encoding bypass testing, and HTTP header evasion into a single command-line tool — designed for use during authorized penetration tests and security assessments.

---

## Features

- **WAF Fingerprinting** — Detects 8+ major WAFs including Cloudflare, AWS WAF, ModSecurity, Akamai, Imperva, Sucuri, F5 BIG-IP ASM, and Fortinet FortiWeb
- **Payload Bypass Scan** — Tests 8 base payloads (SQLi + XSS) across 9 encoding techniques = 72 automated requests
- **Header Evasion Testing** — Tests 10 IP-spoofing headers (X-Forwarded-For, X-Real-IP, CF-Connecting-IP, etc.) to detect IP-based WAF bypass
- **JSON Report Output** — Saves all results (detected WAFs, successful bypasses, evasion headers) to a structured JSON file
- **Modular Design** — Each scan phase can be enabled/disabled independently via CLI flags

### Encoding Techniques Covered

| Technique | Description |
|---|---|
| URL Encode | Standard percent-encoding |
| Double URL Encode | Double-layered percent-encoding |
| HTML Entity Encode | Character-to-HTML entity conversion |
| Hex Encode | Hex percent-encoding |
| Case Variation | Alternating upper/lower case |
| Comment Injection | SQL comment insertion between keywords |
| Whitespace Variation | Space replacement with tab/newline/CRLF |
| Null Byte Injection | Appends `%00` to payloads |
| Overlong UTF-8 | Overlong encoding for `<` and `>` |

---

## Installation

**Requirements:** Python 3.10+

```bash
git clone https://github.com/sameer-aniya/wafi.git
cd wafi
pip install requests
```

---

## Usage

```bash
python wafi.py -u https://target.com/page?id=1
```

### Options

```
  -u, --url         Target URL (required)
  -p, --param       GET parameter to fuzz (default: q)
  -t, --timeout     Request timeout in seconds (default: 10)
  -d, --delay       Delay between requests in seconds (default: 0.3)
  -o, --output      Save results to JSON file
  --no-fingerprint  Skip WAF fingerprinting
  --no-headers      Skip header evasion test
  --no-bypass       Skip payload bypass scan
```

### Examples

```bash
# Full scan with JSON output
python wafi.py -u "https://target.com/search?q=test" -p q -o results.json

# Only WAF fingerprinting, no bypass testing
python wafi.py -u "https://target.com/" --no-bypass --no-headers

# Custom parameter with slower delay
python wafi.py -u "https://target.com/page?id=1" -p id -d 1.0
```

---

## Sample Output

```
  [*] Step 1: WAF Fingerprinting...
  [!] WAF Detected: Cloudflare

  [*] Step 2: Payload Bypass Scan on param 'q'...
  Technique                 Payload (truncated)                 Status   Result
  ───────────────────────── ─────────────────────────────────── ──────── ──────────
  URL Encode                %27%20OR%20%271%27%3D%271           403      BLOCKED
  Double URL Encode         %2527%2520OR%2520%25271%2527%253D%  200      ✓ BYPASSED
  Comment Injection         '/**/OR/**/'1'='1                   200      ✓ BYPASSED

  [*] Step 3: Header Evasion Test...
  X-Forwarded-For                     127.0.0.1            200      ✓ BYPASSED
```

---

## Disclaimer

> **This tool is intended for authorized security testing only.**
> Use WAFI exclusively on systems you own or have explicit written permission to test.
> Unauthorized use against systems without permission is illegal and unethical.
> The author assumes no liability for misuse of this tool.

---

## Author

**Sameer Aniya**
- GitHub: [github.com/sameer-aniya]()
- LinkedIn: [(https://www.linkedin.com/in/sameer-aniya-79154333a)]()

---

## License

This project is intended for educational and authorized penetration testing use only.
