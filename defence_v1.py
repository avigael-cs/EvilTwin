from scapy.all import *
from scapy.layers.dot11 import Dot11Deauth, Dot11ProbeResp
from ap_scanner import setMonitor

interface = ''
max_ssids_per_addr = 5
probe_resp = {}
nr_of_max_deauth = 10
deauth_timespan = 23
deauths = {}


def handler(packet):
    if packet.haslayer(Dot11Deauth):
        deauths.setdefault(packet.addr2, []).append(time.time())
        span = deauths[packet.addr2][-1] - deauths[packet.addr2][0]
        if len(deauths[packet.addr2]) == nr_of_max_deauth and span <= deauth_timespan:
            print(f"Trying to Deauth us: {packet.addr2}")
            del deauths[packet.addr2]

        elif packet.haslayer(Dot11ProbeResp):
            probe_resp.setdefault(packet.addr2, set()).add(packet.info)
            if len(probe_resp[packet.addr2]) == max_ssids_per_addr:
                print(f"{packet.addr2} is spoofing ssid")
                for ssid in probe_resp[packet.addr2]:
                    print(ssid)
                print(" ")
                del probe_resp[packet.addr2]


def defend(iface):
    global interface
    interface = iface
    setMonitor(interface)
    sniff(iface=interface, prn=handler)
