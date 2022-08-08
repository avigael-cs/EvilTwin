iptables --flush
iptables --table nat --append POSTROUTING --out-interface wlan0 -j MASQUERADE 
iptables --append FORWARD --in-interface wlan1 -j ACCEPT 
iptables -t nat -A POSTROUTING -j MASQUERADE
echo 1 > /proc/sys/net/ipv4/ip_forward
cat /proc/sys/net/ipv4/ip_forward