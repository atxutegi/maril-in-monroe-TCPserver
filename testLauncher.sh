#!/bin/sh
#Execute as "sudo sh testLauncher.sh > /dev/null 2>&1 &"
cd maril-in-monroe-TCPserver
sh ssTrace.sh $1 $2 > /dev/null 2>&1 &
#tcpdump -i eth0 'host '$1 -s 0 -n -w "$2".pcap 2>/dev/null &
#tcpdump -i eth0 'host '$1 -s 0 -n -w "$2".pcap &
#tcpdump -i eth0 'host '$1 -s 0 -n -w "$2".pcap 2>/dev/null 2>&1 &
#/usr/sbin/tcpdump -i eth0 "host "$1 -s 0 -n -w "$2".pcap &
/usr/sbin/tcpdump -i eth0 "port 3446 or port 42042 or portrange 12345-12545" -s 0 -n -w "$2".pcap &
