import argparse
from scapy.all import sniff, IP, TCP
from colorama import init, Fore

# Initialize colorama for colored output
init()

def detect_ssh_traffic(packet):
    """Callback function to analyze each captured packet"""
    if packet.haslayer(TCP) and packet.haslayer(IP):
        if packet[TCP].dport == 22 or packet[TCP].sport == 22:
            print(Fore.GREEN + f"[SSH DETECTED] {packet[IP].src}:{packet[TCP].sport} -> {packet[IP].dst}:{packet[TCP].dport}")

def start_sniffing(interface):
    """Function to start sniffing on the specified network interface"""
    print(Fore.CYAN + f"Monitoring SSH traffic on interface: {interface}")
    # Sniff packets on the given interface, filtering only TCP packets (SSH runs over TCP)
    sniff(iface=interface, prn=detect_ssh_traffic, filter="tcp", store=False)

def main():
    parser = argparse.ArgumentParser(description="SSH Traffic Detection Tool")
    parser.add_argument("-i", "--interface", type=str, help="Network interface to sniff on", required=True)

    args = parser.parse_args()

    # Start sniffing on the given interface
    start_sniffing(args.interface)

if __name__ == "__main__":
    main()
