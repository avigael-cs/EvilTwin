from scapy.all import *
import os
import multiprocessing

from scapy.layers.dot11 import Dot11Beacon, Dot11, RadioTap, Dot11Deauth

"""
defence module against evil twin, scan for duplicate networks and disconnect from them if found.
"""

network_dict = {}
# my_macs = [get_if_hwaddr(i) for i in get_if_list()]
my_macs = []
duplicate_aps = {}
unique_ap_names = {}


def sniffAP(packet):
    if packet.haslayer(Dot11Beacon):
        mac_addr = packet[Dot11].addr2
        ap_name = packet[Dot11].info.decode()
        stats = packet[Dot11Beacon].network_stats()
        channel = stats.get("channel")
        if mac_addr not in network_dict.keys() and mac_addr not in my_macs:
            network_dict[mac_addr] = (mac_addr, ap_name, channel)
            print(f"Found AP:{network_dict[mac_addr]}")


# traverse the networks we found, and look if two of them have the same name.
def find_duplicates():
    for mac_addr in network_dict:
        ap_name = network_dict[mac_addr][1]
        if ap_name in unique_ap_names.keys():
            print(f"Duplicated network:\nMAC:{mac_addr} | Name: {ap_name}")
            duplicate_aps[
                mac_addr] = ap_name  # insert both mac addresses into networks, since we don't know which is fake.
            # this is a mac address
            duplicate_aps[unique_ap_names[ap_name]] = ap_name
        else:
            unique_ap_names[ap_name] = mac_addr
    print(duplicate_aps)


def disconnect(bad_ap):
    print("Disconnecting..")
    client_addr = "ff:ff:ff:ff"
    deauth_tap = RadioTap() / Dot11(addr1=client_addr, addr2=bad_ap,
                                    addr3=bad_ap) / Dot11Deauth()  # from all clients on ap to ap
    deauth_tc = RadioTap() / Dot11(addr1=bad_ap, addr2=client_addr,
                                   addr3=client_addr) / Dot11Deauth()  # from ap to all clients
    for i in range(1, 100):
        print(f"sent Deauth - AP: {bad_ap}")
        # sendp since we are working on layer 2
        sendp(deauth_tap, iface=interface, count=100)
        sendp(deauth_tc, iface=interface, count=100)
        time.sleep(2)


def changeChannels(timeout):
    channel = 1
    counter = 0
    while True:
        # os command to switch channels.
        os.system(f"iwconfig {interface} channel {channel}")
        channel = channel % 14 + 1
        time.sleep(2)
        print(f"scanning channel: {channel}")
        counter += 1
        if counter == timeout:
            break


def setMonitor(interface):
    os.system(f"sudo ifconfig {interface} down")
    os.system(f"sudo iwconfig {interface} mode monitor")
    os.system(f"sudo ifconfig {interface} up")


if __name__ == '__main__':
    interface = 'wlx5ca6e686a840'
    setMonitor(interface)
    timeout = 60
    channelChanger = multiprocessing.Process(target=changeChannels, args=(timeout,), daemon=True)
    channelChanger.start()
    sniff(prn=sniffAP, timeout=timeout, iface=interface)
    channelChanger.join()
    find_duplicates()
    if len(duplicate_aps.keys()) > 0:
        print("Found duplicate APs - Disconnecting from internet ")
        for dup_mac in duplicate_aps.keys():
            dc_process = multiprocessing.Process(target=disconnect, args=(dup_mac,))

    print("Finished.")

