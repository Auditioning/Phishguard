"""
PhishGuard — Flask Backend (Groq Edition)
Free AI using Groq's API (14,400 requests/day free)

Setup:
1. pip install flask groq
2. Get free key at https://console.groq.com
3. Paste your key below
4. Run: python app.py
5. Open: http://localhost:5000
"""

import re
import os
import json
import socket
import ssl
import urllib.request
import urllib.parse
from datetime import datetime, timezone

from flask import Flask, render_template, request, jsonify
from groq import Groq

app = Flask(__name__)

_ai = Groq(api_key=os.environ.get("GROQ_API_KEY"))


SUSPICION_THRESHOLD = 10

# ── Hardcoded patterns ────────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "update", "account", "banking",
    "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "support", "confirm", "password", "credential", "billing",
    "urgent", "suspended", "locked", "alert", "immediately",
]

TRUSTED_TLDS  = {".com", ".org", ".net", ".edu", ".gov", ".io", ".co"}
RISKY_TLDS    = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
    ".loan", ".work", ".online", ".site", ".live", ".stream",
    ".bid", ".download", ".review", ".win",
}

TRUSTED_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "ebay",
    "wellsfargo", "chase", "bankofamerica", "citibank",
]

# ── Levenshtein ───────────────────────────────────────────────────────────────

def levenshtein(a, b):
    if a == b: return 0
    if len(a) < len(b): a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(prev[j] + (ca != cb), prev[j+1] + 1, curr[j] + 1))
        prev = curr
    return prev[-1]

# ── Groq AI batch call ────────────────────────────────────────────────────────

def ask_ai_batch(domain, full_url):
    tld = "." + domain.rsplit(".", 1)[-1]
    prompt = f"""Analyse this URL for phishing indicators.

URL: {full_url}
Domain: {domain}
TLD: {tld}

Return ONLY this JSON (no markdown, no explanation):
{{
  "keywords": {{"passed": <bool>, "score": <0-20>, "detail": "<one sentence>"}},
  "brand":    {{"passed": <bool>, "score": <0-30>, "detail": "<one sentence>"}},
  "tld":      {{"passed": <bool>, "score": <0-20>, "detail": "<one sentence>"}}
}}

Scoring rules:
- keywords: 0=clean, 8=1-2 phishing words found, 20=3+ phishing words found
- brand: 0=no impersonation or legitimate domain, 30=known brand in non-official domain
- tld: 0=trusted (.com .org .net .gov .edu .io), 5=uncommon, 20=high-risk free TLD"""

    try:
        response = _ai.chat.completions.create(
            model="llama-3.3-70b-versatile",
            max_tokens=400,
            temperature=0,
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert. Reply ONLY with valid JSON — no markdown, no preamble."},
                {"role": "user",   "content": prompt}
            ],
        )
        raw   = response.choices[0].message.content.strip()
        raw   = re.sub(r"^```(?:json)?\s*|```$", "", raw, flags=re.MULTILINE).strip()
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if not match:
            return {}, False
        parsed = json.loads(match.group())
        if not all(k in parsed for k in ("keywords", "brand", "tld")):
            return {}, False
        return parsed, True
    except Exception as e:
        print(f"[Groq AI error] {e}")
        return {}, False

# ── Detector ──────────────────────────────────────────────────────────────────

class FakeWebsiteDetector:

    def analyze(self, url):
        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        parsed   = urllib.parse.urlparse(url)
        domain   = parsed.netloc.lower().replace("www.", "")
        full_url = url.lower()

        checks = {
            "url_length":      self._check_url_length(url),
            "https":           self._check_https(url),
            "subdomain_abuse": self._check_subdomain_abuse(domain),
            "ip_as_host":      self._check_ip_host(parsed.netloc),
            "special_chars":   self._check_special_chars(domain),
            "typosquatting":   self._check_typosquatting(domain),
            "redirect_count":  self._check_redirects(url),
            "ssl_cert":        self._check_ssl(parsed.netloc),
        }

        phase1_score = sum(c["score"] for c in checks.values() if c["score"] is not None)
        ai_used    = False
        ai_warning = None

        if phase1_score >= SUSPICION_THRESHOLD:
            batch, success = ask_ai_batch(domain, full_url)
            if success:
                ai_used = True
                checks["suspicious_keywords"] = batch["keywords"]
                checks["brand_impersonation"] = batch["brand"]
                checks["risky_tld"]           = batch["tld"]
            else:
                ai_warning = "AI analysis failed — rule-based fallback used. Results may be less accurate."
                checks["suspicious_keywords"] = self._v1_keywords(full_url)
                checks["brand_impersonation"] = self._v1_brand(domain)
                checks["risky_tld"]           = self._v1_tld(domain)
        else:
            checks["suspicious_keywords"] = self._v1_keywords(full_url)
            checks["brand_impersonation"] = self._v1_brand(domain)
            checks["risky_tld"]           = self._v1_tld(domain)

        score, risk_level = self._calculate_risk(checks)

        return {
            "url":         url,
            "domain":      domain,
            "score":       score,
            "risk_level":  risk_level,
            "ai_used":     ai_used,
            "ai_warning":  ai_warning,
            "checks":      checks,
            "analyzed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }

    def _check_url_length(self, url):
        n = len(url)
        if n > 100: return {"passed": False, "score": 20, "detail": f"Very long URL ({n} chars) — common in phishing."}
        if n > 75:  return {"passed": False, "score": 10, "detail": f"Moderately long URL ({n} chars)."}
        return {"passed": True, "score": 0, "detail": f"URL length is normal ({n} chars)."}

    def _check_https(self, url):
        if url.startswith("https://"):
            return {"passed": True, "score": 0, "detail": "HTTPS encryption is active."}
        return {"passed": False, "score": 15, "detail": "No HTTPS — data travels in plain text."}

    def _check_subdomain_abuse(self, domain):
        parts = domain.split(".")
        depth = len(parts[:-2]) if len(parts) > 2 else 0
        if depth >= 3: return {"passed": False, "score": 25, "detail": f"Excessive subdomain depth ({depth} levels)."}
        if depth == 2: return {"passed": False, "score": 10, "detail": "Deep subdomains may mask the real host."}
        return {"passed": True, "score": 0, "detail": "Subdomain structure looks normal."}

    def _check_ip_host(self, netloc):
        host = netloc.split(":")[0]
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
            return {"passed": False, "score": 25, "detail": f"Raw IP address used as host ({host})."}
        return {"passed": True, "score": 0, "detail": "Domain name used, not a raw IP."}

    def _check_special_chars(self, domain):
        if re.findall(r"[-_@!]{2,}", domain):
            return {"passed": False, "score": 15, "detail": "Unusual repeated characters in domain name."}
        if domain.count("-") >= 3:
            return {"passed": False, "score": 10, "detail": f"Many hyphens ({domain.count('-')}) — common in typosquatting."}
        return {"passed": True, "score": 0, "detail": "No unusual character sequences."}

    def _check_typosquatting(self, domain):
        base = domain.rsplit(".", 1)[0].replace("-", "").replace("_", "")
        for brand in TRUSTED_BRANDS:
            dist = levenshtein(base, brand)
            if 0 < dist <= 2 and len(base) >= len(brand) - 1:
                return {"passed": False, "score": 25,
                        "detail": f"'{domain}' is {dist} edit(s) from '{brand}' — likely typosquatting."}
        return {"passed": True, "score": 0, "detail": "No typosquatting pattern detected."}

    def _check_redirects(self, url):
        try:
            req  = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            resp = urllib.request.urlopen(req, timeout=5)
            final = resp.geturl()
            if final != url and urllib.parse.urlparse(final).netloc != urllib.parse.urlparse(url).netloc:
                return {"passed": False, "score": 20, "detail": "Redirects to a different domain."}
            return {"passed": True, "score": 0, "detail": "No cross-domain redirects detected."}
        except Exception as e:
            return {"passed": None, "score": 5, "detail": f"Could not follow redirects: {str(e)[:60]}"}

    def _check_ssl(self, netloc):
        host = netloc.split(":")[0]
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert   = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    org    = issuer.get("organizationName", "unknown")
                    return {"passed": True, "score": 0, "detail": f"Valid SSL cert from {org}."}
        except ssl.SSLCertVerificationError:
            return {"passed": False, "score": 30, "detail": "Invalid or self-signed SSL certificate."}
        except Exception as e:
            return {"passed": None, "score": 5, "detail": f"SSL check skipped: {str(e)[:60]}"}

    def _v1_keywords(self, full_url):
        found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url]
        if len(found) >= 3: return {"passed": False, "score": 20, "detail": f"Suspicious keywords: {', '.join(found[:5])}."}
        if found:           return {"passed": False, "score": 8,  "detail": f"Keyword(s) found: {', '.join(found)}."}
        return {"passed": True, "score": 0, "detail": "No suspicious keywords found."}

    def _v1_brand(self, domain):
        base = domain.split(".")[0]
        for brand in TRUSTED_BRANDS:
            if brand in domain and not domain.endswith(f"{brand}.com") and not domain.endswith(f"{brand}.org"):
                if brand != base:
                    return {"passed": False, "score": 30, "detail": f"Brand '{brand}' found in non-official domain."}
        return {"passed": True, "score": 0, "detail": "No brand impersonation detected."}

    def _v1_tld(self, domain):
        tld = "." + domain.rsplit(".", 1)[-1]
        if tld in RISKY_TLDS:       return {"passed": False, "score": 20, "detail": f"High-risk TLD '{tld}'."}
        if tld not in TRUSTED_TLDS: return {"passed": False, "score": 5,  "detail": f"Uncommon TLD '{tld}'."}
        return {"passed": True, "score": 0, "detail": f"TLD '{tld}' is trusted."}

    def _calculate_risk(self, checks):
        total = min(sum(c["score"] for c in checks.values() if c.get("score") is not None), 100)
        level = "HIGH" if total >= 60 else "MEDIUM" if total >= 30 else "LOW"
        return total, level


detector = FakeWebsiteDetector()

@app.route("/")
def index():
    url = request.args.get("url", "")
    return render_template("index.html", prefill_url=url)

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()
    url  = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    try:
        result = detector.analyze(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))