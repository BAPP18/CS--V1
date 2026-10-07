import os
import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
USER_AGENT = "CS--V1/1.1 (+https://github.com/BAPP18/CS--V1)"


def _extract_cvss(cve):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            cvss_data = metrics[key][0].get("cvssData", {})
            return {
                "version": cvss_data.get("version", "N/A"),
                "severity": cvss_data.get("baseSeverity", "N/A"),
                "score": cvss_data.get("baseScore", "N/A"),
            }
    return {"version": "N/A", "severity": "N/A", "score": "N/A"}


def search_cve(keyword, max_results=10):
    keyword = keyword.strip()
    if not keyword:
        raise ValueError("Keyword tidak boleh kosong.")

    max_results = max(1, min(int(max_results), 50))

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
    }
    headers = {"User-Agent": USER_AGENT}

    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    try:
        response = requests.get(
            NVD_API_URL,
            params=params,
            headers=headers,
            timeout=15,
        )

        if response.status_code == 429:
            print("NVD rate limit tercapai. Coba lagi nanti atau gunakan NVD_API_KEY.")
            return []

        response.raise_for_status()
        data = response.json()
    except requests.exceptions.Timeout:
        print("Request ke NVD timeout.")
        return []
    except requests.exceptions.RequestException as exc:
        print(f"Gagal mengambil data dari NVD: {exc}")
        return []
    except ValueError:
        print("Respons NVD bukan JSON yang valid.")
        return []

    vulnerabilities = data.get("vulnerabilities", [])
    total = data.get("totalResults", 0)

    results = []
    for item in vulnerabilities:
        cve = item.get("cve", {})
        descriptions = cve.get("descriptions", [])
        desc_text = next(
            (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
            "No description",
        )
        cvss = _extract_cvss(cve)

        results.append({
            "id": cve.get("id", "N/A"),
            "description": desc_text,
            "cvss_version": cvss["version"],
            "severity": cvss["severity"],
            "score": cvss["score"],
        })

    print(
        f"\nDitemukan {total} CVE untuk keyword '{keyword}'. "
        f"Menampilkan {len(results)} hasil teratas:\n"
    )

    for result in results:
        print(
            f"[{result['id']}] Severity: {result['severity']} | "
            f"Score: {result['score']} | CVSS: {result['cvss_version']}"
        )
        print(f"  {result['description'][:180]}...")
        print("-" * 60)

    print(
        "\nCatatan: kecocokan keyword dengan CVE tidak membuktikan bahwa "
        "suatu host/sistem benar-benar vulnerable. Validasi versi, konfigurasi, "
        "dan applicability secara terpisah."
    )

    return results


def run():
    print("\n=== CVE LOOKUP (NVD API) ===")
    print("Contoh keyword: 'apache 2.4.49' atau 'openssl 1.0.1'")

    keyword = input("Software/keyword: ").strip()
    if not keyword:
        print("Keyword tidak boleh kosong.")
        return

    search_cve(keyword)


if __name__ == "__main__":
    run()
