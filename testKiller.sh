#!/bin/sh
kill -9 `ps -ef | grep 'tcpdum\| ssTrace' | awk '{print $2}'`
name=`ls | grep 2016 | grep pcap | sed 's/\.pcap//'`
chmod 777 "$name"*
editcap -C 122:1420 "$name".pcap "$name"_strip.pcap
chmod 777 "$name"_strip.pcap
mkdir -p "$name"_folder
mv 2016*.pcap "$name"_folder/
mv 2016*.txt "$name"_folder/
mv output* "$name"_folder/
kill -9 `ps -ef | grep 'maril' | tail -n +2 | awk '{print $2}'`
