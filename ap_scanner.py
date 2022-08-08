from scapy.all import *
import multiprocessing
import time
import os
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11

"""
Use:
Run main (or wrap in another function), enter interface to fit your card.
wait until scan if complete and choose a network
returns a tuple of (mac address,ap name,channel, and signal dbm)
"""

global network_dict
network_dict = {}  # holds network stats - mac,name,channel
network_index = {}  # for easy access to network using index
my_macs = []  # = [get_if_hwaddr(i) for i in get_if_list()] # so we don't attack ourselves
ap_client_list = {}


def sniffAP(pkt):
    if pkt.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        mac_addr = pkt[Dot11].addr2
        # get the name of it
        ap_name = pkt[Dot11Elt].info.decode()
        # get dbm signal
        try:
            dbm_signal = pkt.dBm_AntSignal
        except:
            dbm_signal = "N/A"
        # extract network stats for channel
        stats = pkt[Dot11Beacon].network_stats()
        # get the channel of the AP
        channel = stats.get("channel")
        if mac_addr not in network_dict.keys() and mac_addr not in my_macs:
            network_dict[mac_addr] = (mac_addr, ap_name, channel, dbm_signal)
            print(f"Found AP:{network_dict[mac_addr]}")
            ap_client_list[mac_addr] = []

# changing channel every 2 seconds, for timeout times.
def changeChannel(timeout: int, interface):
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


# called after scan was finished, allows user to choose network by index of display, or mac address.
def pickNetwork():
    mac_ok = False
    while not mac_ok:
        network_mac = input(
            "Please enter an index (starting from 0) or MAC address of the network you want to attack: ")
        if not any(c.isalpha() for c in str(network_mac)):  # if index is entered there will be no letters
            if int(network_mac) not in network_index.keys():
                print("ERROR, not a valid index")
                continue
            else:
                print("Valid index")
                network = network_dict.get(network_index.get(int(network_mac)))
                print(f"Chosen network: {network}")
                return network
        if network_mac not in network_dict.keys():
            print("ERROR, not a valid MAC address")
            continue
        if network_mac in network_dict.keys():
            print(f"Chosen network: {network_dict.get(network_mac)}")
            return network_dict.get(network_mac)


def scanClients(packet):
    if packet.FCfield:
        DS = packet.FCfield & 0x3
        to_DS = DS & 0x1 != 0
        from_DS = DS & 0x2 != 0

        #  addr1 is ap | addr2 is client,
        if to_DS and not from_DS:
            client_mac = packet.addr2
            if packet.addr2 not in ap_client_list.setdefault(packet.addr1, []):
                print(f"Possible client: {client_mac}")
                ap_client_list[packet.addr1].append(packet.addr2)


def pickClient():
    client_ok = False
    while not client_ok:
        client_mac = input("Please enter an index (starting from 0) or MAC address of the client you want to attack: ")
        if not any(c.isalpha() for c in str(client_mac)):  # if index is entered there will be no letters
            if int(client_mac) > len(ap_client_list[target_ap]):
                print("ERROR, not a valid index")
                continue
            else:
                print("Valid index")
                client_mac = ap_client_list[int(client_mac)]
                print(f"MAC chosen: {client_mac}")
                return client_mac
        if client_mac not in ap_client_list[target_ap]:
            print("Error, not a valid MAC address")
            continue
        if client_mac in ap_client_list[target_ap]:
            # in ap client dict, get the mac address stored in tuple[0]
            print(f"MAC chosen: {client_mac}")
            return client_mac


def setMonitor(interface):
    os.system(f"sudo ifconfig {interface} down")
    os.system(f"sudo iwconfig {interface} mode monitor")
    os.system(f"sudo ifconfig {interface} up")


def ap_client_scanner(interface):
    # interface name
    global target_ap
    setMonitor(interface)
    # if no timeout is passed, default to 60 seconds
    timeout = 30

    # ----------------------------PART 1: scan and pick network ---------------------
    # start the thread that changes channels all the networks
    #changeChannel - for the 14 channel
    channel_changer = multiprocessing.Process(target=changeChannel, args=(timeout, interface), daemon=True)
    channel_changer.start()
    sniff(prn=sniffAP, iface=interface, timeout=timeout)
    channel_changer.join()
    # Create network index dict, and prompt picking of a network.
    i = 0
    os.system('clear')
    print("Available Networks:")
    for network in network_dict.keys():
        network_addr = network_dict.get(network)[0]
        network_name = network_dict.get(network)[1]
        channel = network_dict.get(network)[2]
        dbm = network_dict.get(network)[3]
        print(f"INDEX: {i} | MAC: {network_addr} | NAME: {network_name} | CHANNEL: {channel} | SIGNAL DBM: {dbm}")
        network_index[i] = network
        i += 1
    chosen_network = pickNetwork()
    chosen_network_mac = chosen_network[0]
    # --------------------------------------------------------------------------------------------------
    # ----------------------------PART 2: scan and pick client from chosen network ---------------------

    # define a dictionary for each ap inside a general dict
    channel_changer = multiprocessing.Process(target=changeChannel, args=(timeout, interface), daemon=True)
    channel_changer.start()
    target_ap = chosen_network_mac
    sniff(iface=interface, prn=scanClients, timeout=timeout)
    channel_changer.join()
    i = 0
    os.system('clear')
    print("Possible Clients:")
    for client in ap_client_list[target_ap]:
        client_mac = client
        print(f"Index: {i} | MAC: {client_mac}")
        i += 1
    chosen_client_mac = pickClient()
    # print(chosen_client_mac)
    return chosen_network, chosen_client_mac

