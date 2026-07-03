"""
Cybersecurity Toolkit - Main Menu
Jalankan: python main.py
Lalu pilih tool yang mau dijalankan dari menu interaktif.
"""

import sys
from modules import (
    port_scanner,
    password_tool,
    log_analyzer,
    vuln_scanner,
    phishing_detector,
    packet_sniffer,
)

MENU = {
    "1": ("Port Scanner", port_scanner.run),
    "2": ("Password Strength Checker + Generator", password_tool.run),
    "3": ("Log Analyzer", log_analyzer.run),
    "4": ("Vulnerability Scanner (NVD API)", vuln_scanner.run),
    "5": ("Phishing URL Detector", phishing_detector.run),
    "6": ("Network Packet Sniffer", packet_sniffer.run),
    "0": ("Keluar", None),
}


def show_menu():
    print("\n" + "=" * 50)
    print(" CYBERSECURITY TOOLKIT")
    print("=" * 50)
    for key, (name, _) in MENU.items():
        print(f" [{key}] {name}")
    print("=" * 50)


def main():
    while True:
        show_menu()
        choice = input("Pilih menu: ").strip()

        if choice not in MENU:
            print("Pilihan tidak valid, coba lagi.")
            continue

        name, func = MENU[choice]

        if choice == "0":
            print("Keluar dari toolkit. Sampai jumpa!")
            sys.exit(0)

        try:
            func()
        except KeyboardInterrupt:
            print("\nDibatalkan oleh user.")
        except Exception as e:
            print(f"Terjadi error: {e}")

        input("\nTekan Enter untuk kembali ke menu...")


if __name__ == "__main__":
    main()
