nmcli device status
sudo echo "[keyfile]" > /etc/NetworkManager/conf.d/99-unmanaged-devices.conf
sudo echo "unmanaged-devices=interface-name:wlan1" >> /etc/NetworkManager/conf.d/99-unmanaged-devices.conf
cat /etc/NetworkManager/conf.d/99-unmanaged-devices.conf
sudo service NetworkManager restart