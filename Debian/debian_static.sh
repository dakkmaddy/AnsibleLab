#!/bin/bash
#
systemctl stop NetworkManager.service
systemctl disable NetworkManager.service
cat << EOF > /etc/network/interface
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
allow-hotplug enp0s3
iface enp0s3 inet static
      address 10.0.0.240
      netmask 255.255.255.0
      gateway 10.0.0.1

EOF
echo "nameserver 10.0.0.1" >> /etc/resolv.conf
service networking restart
