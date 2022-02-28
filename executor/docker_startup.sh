#!/bin/sh

rm -r -f /app/reports/*
dhcpcd
dnsmasq
/etc/init.d/dbus start
bluetoothd &
# set up routing from ethernet to wlan
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT

export TMP=/app/tmp

if [ -z "$TEST_SCRIPT" ]; then
  TEST_SCRIPT="run_tests.sh"
fi

RUN_TESTS_COMMAND="./utf_core/${TEST_SCRIPT}"

echo ""
echo Running "$RUN_TESTS_COMMAND" test script
echo ""
eval $RUN_TESTS_COMMAND
