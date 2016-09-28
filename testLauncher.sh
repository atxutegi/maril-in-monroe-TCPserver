#!/bin/sh
#Execute as "sudo sh testLauncher.sh > /dev/null 2>&1 &"
sh ssTrace.sh $1 $2 &
tcpdump -i eth0 "host $1" -s 0 -n -w "$2".pcap &
