#!/bin/sh
airmon-ng check kill
service hostapd stop
service apache2 stop
service dnsmasq stop
service rpcbind stop
killall dnsmasq
killall hostapd
sudo iw dev wlan1mon interface del
service NetworkManager restart
