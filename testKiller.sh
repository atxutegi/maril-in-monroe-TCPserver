#!/bin/sh
cd /home/operario/maril-in-monroe-TCPserver
first=`ps -ef | grep '[ssTra]ce' | head -1 |awk '{print $2}'`
nameFolder=`ps -ef | grep 'ssTrace' | awk '{print $11}' | head -1`
ip=`ps -ef | grep 'ssTrace' | awk '{print $10}' | head -1`
if [ "$first" != "" ]
then
	ps -ef | grep "[ssTra]ce" |awk '{print $2}' | xargs kill
	killall tcpdump
fi
if [ "$nameFolder" != "" ] 
then
	chmod 777 "$nameFolder"*
	editcap -C 122:1420 "$nameFolder".pcap "$nameFolder"_strip.pcap
	chmod 777 "$nameFolder"_strip.pcap
	mkdir -p "$nameFolder"_"$ip"_folder
	mv "$nameFolder"*.pcap "$nameFolder"_"$ip"_folder/
	mv "$nameFolder"*.txt "$nameFolder"_"$ip"_folder/
	mv output* "$nameFolder"_"$ip"_folder/
else
	nameFail=`ls | grep '\.pcap' |sed 's/\.pcap//'`
	editcap -C 122:1420 "$nameFail".pcap "$nameFail"_strip.pcap
        chmod 777 "$nameFail"_strip.pcap
        mkdir -p "$nameFail"_FailedFolder
        mv "$nameFail"*.pcap "$nameFail"_FailedFolder/
        mv "$nameFail"*.txt "$nameFail"_FailedFolder/

fi
