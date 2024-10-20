import argparse
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from colorama import init, Fore

# Initialize colorama for colored output
init()


def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        # Display based on protocol type in different colors
        if TCP in packet:
            print(Fore.GREEN + f"[TCP] {ip_src} -> {ip_dst}")
        elif UDP in packet:
            print(Fore.BLUE + f"[UDP] {ip_src} -> {ip_dst}")
        elif ICMP in packet:
            print(Fore.YELLOW + f"[ICMP] {ip_src} -> {ip_dst}")
        else:
            print(Fore.RED + f"[Other Protocol] {ip_src} -> {ip_dst}")
    else:
        print(Fore.RED + "Non-IP Packet Detected")


def main():
    parser = argparse.ArgumentParser(description="Network Traffic Monitoring Tool")
    parser.add_argument("-i", "--interface", type=str, help="Specify the network interface", required=True)
    args = parser.parse_args()

    print(Fore.CYAN + f"Monitoring traffic on interface: {args.interface}")

    # Start sniffing packets on the specified interface
    sniff(iface=args.interface, prn=packet_callback, store=False)


if __name__ == "__main__":
    main()
