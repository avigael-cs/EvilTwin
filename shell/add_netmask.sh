#!/bin/sh
sudo ifconfig wlan1 up 10.100.101.1 netmask 255.255.255.0
sudo route add -net 10.100.101.0 netmask 255.255.255.0 gw 10.100.101.1
sudo ip link set wlan1 up
