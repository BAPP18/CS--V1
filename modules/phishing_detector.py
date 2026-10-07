import ipaddress
import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "banking",
    "confirm", "signin", "webscr", "password", "urgent"
]

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd"
}


def _normalize_url(url):
    value = url.strip()
    if "://" not in value:
        value = "http://" + value
    return value


def _is_ip_host(hostname):
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _is_shortener(hostname):
    if not hostname:
        return False
    host = hostname.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in SHORTENER_DOMAINS)


def analyze_url(url):
    normalized = _normalize_url(url)
    parsed = urlparse(normalized)
    hostname = (parsed.hostname or "").lower()
    path_and_query = f"{parsed.path}?{parsed.query}".lower()

    score = 0
    reasons = []

    if _is_ip_host(hostname):
        score += 3
        reasons.append("Domain menggunakan IP address langsung")

    if len(url) > 75:
        score += 1
        reasons.append("URL sangat panjang")

    if hostname.count(".") > 3:
        score += 2
        reasons.append("Terlalu banyak subdomain")

    if "@" in url:
        score += 3
        reasons.append("Mengandung karakter '@' yang dapat menyamarkan tujuan URL")

    if hostname.count("-") >= 2:
        score += 1
        reasons.append("Domain mengandung banyak tanda hubung (-)")

    if _is_shortener(hostname):
        score += 2
        reasons.append("Menggunakan URL shortener")

    found_keywords = sorted({
        kw for kw in SUSPICIOUS_KEYWORDS
        if kw in hostname or kw in path_and_query
    })
    if found_keywords:
        score += min(len(found_keywords), 4)
        reasons.append(f"Mengandung kata berisiko: {', '.join(found_keywords)}")

    if parsed.scheme != "https":
        score += 1
        reasons.append("Tidak menggunakan HTTPS")

    if "//" in parsed.path:
        score += 1
        reasons.append("Path mengandung double slash")

    if score >= 6:
        verdict = "TINGGI"
    elif score >= 3:
        verdict = "SEDANG"
    else:
        verdict = "RENDAH"

    return {
        "url": url,
        "normalized_url": normalized,
        "hostname": hostname,
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
    }


def run():
    print("\n=== PHISHING URL DETECTOR ===")
    url = input("Masukkan URL yang mau dicek: ").strip()
    if not url:
        print("URL tidak boleh kosong.")
        return

    result = analyze_url(url)

    print(f"\nURL       : {result['url']}")
    print(f"Risk Score: {result['score']}")
    print(f"Verdict   : {result['verdict']}")
    print("Catatan   : hasil ini heuristik, bukan bukti pasti phishing.")

    if result["reasons"]:
        print("Indikator:")
        for reason in result["reasons"]:
            print(f"  - {reason}")
    else:
        print("Tidak ditemukan indikator mencurigakan dari rule yang tersedia.")


if __name__ == "__main__":
    run()
