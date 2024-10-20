import argparse
from scapy.all import sniff, sendp, IP, TCP
from colorama import init, Fore

# Initialize colorama for colored output
init()


def modify_packet(packet):
    """Function to modify and resend the packet"""
    if packet.haslayer(IP) and packet.haslayer(TCP):
        # Print original packet information
        print(
            Fore.CYAN + f"Original Packet: {packet[IP].src} -> {packet[IP].dst} [Port: {packet[TCP].sport} -> {packet[TCP].dport}]")

        # Modify packet details (e.g., change the destination IP and port)
        modified_packet = packet.copy()
        modified_packet[IP].dst = "192.168.1.100"  # Change destination IP
        modified_packet[TCP].dport = 8080  # Change destination port

        # Delete checksum to have Scapy recalculate it
        del modified_packet[IP].chksum
        del modified_packet[TCP].chksum

        # Resend the modified packet
        sendp(modified_packet, iface=interface, verbose=False)
        print(
            Fore.GREEN + f"Modified and Resent Packet: {packet[IP].src} -> {modified_packet[IP].dst} [Port: {packet[TCP].sport} -> {modified_packet[TCP].dport}]")


def start_sniffing(interface, filter_criteria):
    """Function to start sniffing and apply packet manipulation"""
    print(Fore.YELLOW + f"Sniffing on interface: {interface} with filter: {filter_criteria}")

    # Sniff traffic based on the filter criteria
    sniff(iface=interface, filter=filter_criteria, prn=modify_packet, store=False)


def main():
    parser = argparse.ArgumentParser(description="Packet Manipulation Tool")
    parser.add_argument("-i", "--interface", type=str, help="Network interface to sniff on", required=True)
    parser.add_argument("-f", "--filter", type=str, help="BPF filter (e.g., 'tcp' or 'udp')", required=False,
                        default="tcp")

    args = parser.parse_args()

    # Start sniffing on the specified interface and apply packet modification
    global interface
    interface = args.interface
    start_sniffing(interface, args.filter)


if __name__ == "__main__":
    main()
