import argparse
from scapy.all import IP, ICMP, UDP, sr1
import time

def traceroute(target_ip, max_hops=30, timeout=2, protocol="ICMP"):
    ttl = 1
    print(f"Traceroute to {target_ip}, max {max_hops} hops:\n")

    while ttl <= max_hops:
        # Prepare the packet with the given TTL
        ip_layer = IP(dst=target_ip, ttl=ttl)

        # Use ICMP or UDP based on user input
        if protocol.upper() == "ICMP":
            pkt = ip_layer / ICMP()
        else:
            pkt = ip_layer / UDP(dport=33434)  # Using a high UDP port

        # Send the packet and wait for a response
        start_time = time.time()
        response = sr1(pkt, timeout=timeout, verbose=False)
        round_trip_time = (time.time() - start_time) * 1000  # Convert to milliseconds

        if response is None:
            print(f"{ttl}\t*\tRequest timed out")
        else:
            if response.haslayer(ICMP):
                src_ip = response[IP].src
                print(f"{ttl}\t{src_ip}\t{round_trip_time:.2f} ms")
                # If we reach the target, exit
                if src_ip == target_ip:
                    print("Reached the destination.")
                    break
            else:
                print(f"{ttl}\t*\tUnexpected response")

        ttl += 1

def main():
    parser = argparse.ArgumentParser(description="Traceroute Tool using Scapy")
    parser.add_argument("-t", "--target", type=str, help="Target IP address or domain", required=True)
    parser.add_argument("-p", "--protocol", type=str, choices=["ICMP", "UDP"], default="ICMP", help="Protocol to use (ICMP or UDP)")
    parser.add_argument("-m", "--max-hops", type=int, default=30, help="Maximum number of hops")
    parser.add_argument("-o", "--timeout", type=int, default=2, help="Timeout for each hop (seconds)")

    args = parser.parse_args()

    traceroute(args.target, max_hops=args.max_hops, timeout=args.timeout, protocol=args.protocol)

if __name__ == "__main__":
    main()
