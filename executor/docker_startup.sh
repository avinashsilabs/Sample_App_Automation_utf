#!/bin/sh

dhcpcd
dnsmasq
/etc/init.d/dbus start
bluetoothd &
# set up routing from ethernet to wlan
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT

