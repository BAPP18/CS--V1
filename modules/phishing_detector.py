"""
Module 5: Phishing URL Detector (rule-based heuristic)
Tidak butuh dataset/training model - cocok untuk demo cepat & portofolio.
"""

import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "banking",
    "confirm", "signin", "webscr", "password", "urgent"
]

SHORTENER_DOMAINS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd"
]


def analyze_url(url):
    score = 0
    reasons = []

    parsed = urlparse(url if "://" in url else "http://" + url)
    domain = parsed.netloc
    path = parsed.path.lower()

    # 1. IP address as domain
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain.split(":")[0]):
        score += 3
        reasons.append("Domain menggunakan IP address langsung (mencurigakan)")

    # 2. URL length
    if len(url) > 75:
        score += 1
        reasons.append("URL sangat panjang")

    # 3. Banyak subdomain / titik
    if domain.count(".") > 3:
        score += 2
        reasons.append("Terlalu banyak subdomain")

    # 4. Menggunakan '@' di URL (trik redirect)
    if "@" in url:
        score += 3
        reasons.append("Mengandung karakter '@' (teknik penyamaran redirect)")

    # 5. Hyphen berlebihan di domain
    if domain.count("-") >= 2:
        score += 1
        reasons.append("Domain mengandung banyak tanda hubung (-)")

    # 6. Shortener
    if any(short in domain for short in SHORTENER_DOMAINS):
        score += 2
        reasons.append("Menggunakan URL shortener (menyembunyikan tujuan asli)")

    # 7. Keyword mencurigakan
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url.lower()]
    if found_keywords:
        score += len(found_keywords)
        reasons.append(f"Mengandung kata mencurigakan: {', '.join(found_keywords)}")

    # 8. Tidak pakai HTTPS
    if parsed.scheme != "https":
        score += 1
        reasons.append("Tidak menggunakan HTTPS")

    # 9. Double slash di path (redirect trick)
    if "//" in path:
        score += 1
        reasons.append("Path mengandung '//' (kemungkinan open redirect)")

    if score >= 6:
        verdict = "TINGGI - kemungkinan besar PHISHING"
    elif score >= 3:
        verdict = "SEDANG - patut dicurigai"
    else:
        verdict = "RENDAH - kemungkinan aman"

    print(f"\nURL       : {url}")
    print(f"Risk Score: {score}")
    print(f"Verdict   : {verdict}")
    if reasons:
        print("Alasan:")
        for r in reasons:
            print(f"  - {r}")
    else:
        print("Tidak ditemukan indikator mencurigakan.")


def run():
    print("\n=== PHISHING URL DETECTOR ===")
    url = input("Masukkan URL yang mau dicek: ").strip()
    if not url:
        print("URL tidak boleh kosong.")
        return
    analyze_url(url)


if __name__ == "__main__":
    run()
