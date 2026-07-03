# Cybersecurity Toolkit

Kumpulan tools cybersecurity sederhana dalam satu menu interaktif berbasis Python.
Dibuat sebagai portofolio pembelajaran cybersecurity, mencakup network security, application security, dan security automation.

## Fitur

| No | Tool | Deskripsi |
|----|------|-----------|
| 1 | Port Scanner | Scan port terbuka pada target IP/host secara multi-threaded |
| 2 | Password Strength Checker + Generator | Cek kekuatan password (entropy, pola umum) & generate password aman |
| 3 | Log Analyzer | Deteksi pola mencurigakan (brute force SSH, directory scanning) dari log file |
| 4 | Vulnerability Scanner | Cari CVE terkait software/versi tertentu via NVD API |
| 5 | Phishing URL Detector | Analisis heuristik URL untuk mendeteksi ciri-ciri phishing |
| 6 | Network Packet Sniffer | Capture & tampilkan traffic jaringan (TCP/UDP) menggunakan Scapy |

## Instalasi

```bash
git clone https://github.com/BAPPI8/cybersecurity-toolkit.git
cd cybersecurity-toolkit
pip install -r requirements.txt
```

## Cara Menjalankan

```bash
python main.py
```

Setelah dijalankan, akan muncul menu interaktif seperti berikut:

```
==================================================
 CYBERSECURITY TOOLKIT
==================================================
 [1] Port Scanner
 [2] Password Strength Checker + Generator
 [3] Log Analyzer
 [4] Vulnerability Scanner (NVD API)
 [5] Phishing URL Detector
 [6] Network Packet Sniffer
 [0] Keluar
==================================================
Pilih menu:
```

Tinggal ketik angka sesuai tool yang ingin dijalankan.

## Catatan

- **Port Scanner**: gunakan hanya pada sistem/jaringan yang memang milik sendiri atau sudah punya izin resmi.
- **Packet Sniffer**: butuh hak akses admin/root (`sudo python main.py` di Linux/Mac).
- **Vulnerability Scanner**: butuh koneksi internet karena mengambil data dari NVD (National Vulnerability Database).
- **Phishing Detector**: berbasis rule/heuristik sederhana, bukan pengganti tools deteksi phishing profesional.

## Disclaimer

Project ini dibuat untuk tujuan edukasi dan portofolio. Gunakan semua tools secara etis dan hanya pada sistem yang sudah memiliki izin.

## Struktur Project

```
cybersecurity-toolkit/
├── main.py
├── requirements.txt
├── README.md
└── modules/
    ├── port_scanner.py
    ├── password_tool.py
    ├── log_analyzer.py
    ├── vuln_scanner.py
    ├── phishing_detector.py
    └── packet_sniffer.py
```
