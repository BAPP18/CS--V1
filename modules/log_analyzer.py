import re
from collections import defaultdict, Counter

FAILED_SSH_PATTERN = re.compile(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)")
ACCESS_LOG_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+).*\[(?P<date>.*?)\].*"(?P<method>\w+) (?P<path>.*?) HTTP.*" (?P<status>\d+)'
)

BRUTE_FORCE_THRESHOLD = 5
SCAN_THRESHOLD = 20


def analyze_ssh_log(lines):
    failed_attempts = defaultdict(int)
    for line in lines:
        match = FAILED_SSH_PATTERN.search(line)
        if match:
            failed_attempts[match.group(1)] += 1

    print("\n--- SSH Failed Login Analysis ---")
    if not failed_attempts:
        print("Tidak ada pola failed SSH login ditemukan.")
        return

    for ip, count in sorted(failed_attempts.items(), key=lambda x: -x[1]):
        flag = " <-- SUSPICIOUS (possible brute force)" if count > BRUTE_FORCE_THRESHOLD else ""
        print(f"{ip:<16} failed attempts: {count}{flag}")


def analyze_access_log(lines):
    ip_requests = Counter()
    ip_404 = Counter()
    status_counter = Counter()

    for line in lines:
        match = ACCESS_LOG_PATTERN.search(line)
        if match:
            ip = match.group("ip")
            status = match.group("status")
            ip_requests[ip] += 1
            status_counter[status] += 1
            if status == "404":
                ip_404[ip] += 1

    if not ip_requests:
        return False

    print("\n--- Web Access Log Analysis ---")
    print("Top 5 IP paling aktif:")
    for ip, count in ip_requests.most_common(5):
        print(f"  {ip:<16} {count} requests")

    print("\nStatus code distribution:")
    for status, count in status_counter.most_common():
        print(f"  {status}: {count}")

    print("\nPotensi directory/vulnerability scanning (banyak 404):")
    suspicious = [(ip, c) for ip, c in ip_404.items() if c > SCAN_THRESHOLD]
    if suspicious:
        for ip, count in sorted(suspicious, key=lambda x: -x[1]):
            print(f"  {ip:<16} {count} x 404  <-- SUSPICIOUS")
    else:
        print("  Tidak ada IP mencurigakan.")

    return True


def run():
    print("\n=== LOG ANALYZER ===")
    filepath = input("Path ke file log: ").strip()

    try:
        with open(filepath, "r", errors="ignore") as f:
            lines = f.readlines()
    except FileNotFoundError:
        print(f"File tidak ditemukan: {filepath}")
        return

    print(f"Menganalisis {len(lines)} baris log dari: {filepath}")

    is_access_log = analyze_access_log(lines)
    if not is_access_log:
        analyze_ssh_log(lines)


if __name__ == "__main__":
    run()
