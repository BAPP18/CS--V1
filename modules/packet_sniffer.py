try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = "OTHER"

        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"[{proto}] {src_ip}:{sport} -> {dst_ip}:{dport}")
        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"[{proto}] {src_ip}:{sport} -> {dst_ip}:{dport}")
        else:
            print(f"[{proto}] {src_ip} -> {dst_ip}")


def run():
    print("\n=== NETWORK PACKET SNIFFER ===")

    if not SCAPY_AVAILABLE:
        print("Library 'scapy' belum terinstall.")
        print("Install dulu dengan: pip install scapy")
        return

    print("PERINGATAN: butuh hak akses admin/root untuk sniffing.")
    iface = input("Interface (kosongkan untuk default): ").strip()
    count_input = input("Jumlah paket yang mau ditangkap [default 20]: ").strip()
    count = int(count_input) if count_input else 20

    print(f"\nMenangkap {count} paket... (Ctrl+C untuk stop lebih awal)\n")
    try:
        if iface:
            sniff(iface=iface, prn=process_packet, count=count, store=False)
        else:
            sniff(prn=process_packet, count=count, store=False)
    except PermissionError:
        print("Permission denied. Jalankan script dengan sudo/administrator.")
    except KeyboardInterrupt:
        print("\nSniffing dihentikan oleh user.")


if __name__ == "__main__":
    run()
