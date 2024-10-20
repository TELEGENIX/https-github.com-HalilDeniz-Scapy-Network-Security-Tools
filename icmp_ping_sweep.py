import argparse
from scapy.all import ICMP, IP, sr1, conf
import time


def ping_sweep(network, start_ip, end_ip):
    conf.verb = 0  # Disable verbose output from Scapy

    print(f"Starting ICMP Ping Sweep on {network}.{start_ip} to {network}.{end_ip}...")

    for ip in range(start_ip, end_ip + 1):
        ip_address = f"{network}.{ip}"
        pkt = IP(dst=ip_address) / ICMP()

        # Send the packet and wait for a reply
        response = sr1(pkt, timeout=1, verbose=False)

        if response:
            print(f"{ip_address} is alive")
        else:
            print(f"{ip_address} did not respond")


def main():
    parser = argparse.ArgumentParser(description="ICMP Ping Sweep Tool")
    parser.add_argument("-n", "--network", type=str, help="Target network (e.g., 192.168.1)", required=True)
    parser.add_argument("-s", "--start", type=int, help="Start IP (last octet)", required=True)
    parser.add_argument("-e", "--end", type=int, help="End IP (last octet)", required=True)

    args = parser.parse_args()

    ping_sweep(args.network, args.start, args.end)


if __name__ == "__main__":
    main()
