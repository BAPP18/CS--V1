"""
Module 4: Simple Vulnerability Scanner
Cek CVE untuk software/versi tertentu menggunakan NVD (National Vulnerability Database) API.
Butuh koneksi internet. Install dulu: pip install requests
"""

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def search_cve(keyword, max_results=10):
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results
    }
    try:
        response = requests.get(NVD_API_URL, params=params, timeout=15)
        response.raise_for_status()
        data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Gagal mengambil data dari NVD: {e}")
        return

    vulnerabilities = data.get("vulnerabilities", [])
    total = data.get("totalResults", 0)

    print(f"\nDitemukan {total} CVE untuk keyword '{keyword}'. Menampilkan {len(vulnerabilities)} teratas:\n")

    for item in vulnerabilities:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "N/A")
        descriptions = cve.get("descriptions", [])
        desc_text = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description")

        metrics = cve.get("metrics", {})
        severity = "N/A"
        score = "N/A"
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]
            severity = cvss.get("baseSeverity", "N/A")
            score = cvss.get("baseScore", "N/A")
        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0]["cvssData"]
            score = cvss.get("baseScore", "N/A")

        print(f"[{cve_id}] Severity: {severity} | Score: {score}")
        print(f"  {desc_text[:150]}...")
        print("-" * 60)


def run():
    print("\n=== VULNERABILITY SCANNER (NVD API) ===")
    print("Masukkan nama software + versi, contoh: 'apache 2.4.49' atau 'openssl 1.0.1'")
    keyword = input("Software/keyword: ").strip()
    if not keyword:
        print("Keyword tidak boleh kosong.")
        return
    search_cve(keyword)


if __name__ == "__main__":
    run()
