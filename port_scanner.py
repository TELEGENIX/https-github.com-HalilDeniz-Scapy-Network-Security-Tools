import argparse
from scapy.all import IP, TCP, UDP, sr1, sr
from colorama import init, Fore

# Initialize colorama for colored output
init()

def scan_tcp_port(ip, port):
    # Crafting a TCP packet
    tcp_packet = IP(dst=ip) / TCP(dport=port, flags='S')  # SYN packet
    response = sr1(tcp_packet, timeout=1, verbose=False)

    if response and response.haslayer(TCP):
        if response[TCP].flags == 'SA':  # SYN-ACK received, port is open
            print(Fore.GREEN + f"TCP Port {port} is open")
        elif response[TCP].flags == 'RA':  # RST-ACK received, port is closed
            print(Fore.RED + f"TCP Port {port} is closed")
    else:
        print(Fore.YELLOW + f"TCP Port {port} is filtered (no response)")

def scan_udp_port(ip, port):
    # Crafting a UDP packet
    udp_packet = IP(dst=ip) / UDP(dport=port)
    response = sr1(udp_packet, timeout=1, verbose=False)

    if response is None:
        print(Fore.YELLOW + f"UDP Port {port} is open/filtered (no response)")
    elif response.haslayer(UDP):
        print(Fore.GREEN + f"UDP Port {port} is open")
    elif response.haslayer(ICMP):
        print(Fore.RED + f"UDP Port {port} is closed (ICMP unreachable)")

def main():
    parser = argparse.ArgumentParser(description="Simple Port Scanner using Scapy")
    parser.add_argument("-t", "--target", type=str, help="Target IP address", required=True)
    parser.add_argument("-p", "--ports", type=str, help="Port range (e.g. 20-80)", required=True)
    parser.add_argument("--udp", action="store_true", help="Enable UDP scanning")

    args = parser.parse_args()

    ip = args.target
    port_range = args.ports.split("-")
    start_port = int(port_range[0])
    end_port = int(port_range[1])

    print(Fore.CYAN + f"Starting scan on target: {ip}, ports: {start_port}-{end_port}")

    for port in range(start_port, end_port + 1):
        if args.udp:
            scan_udp_port(ip, port)
        else:
            scan_tcp_port(ip, port)

if __name__ == "__main__":
    main()
