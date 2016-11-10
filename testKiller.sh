#!/bin/sh
#$1=NodeID $2=Operator
cd /home/operario/maril-in-monroe-TCPserver
first=`ps -ef | grep '[ssTra]ce' | head -1 |awk '{print $2}'`
nameFolder=`ps -ef | grep 'ssTrace' | awk '{print $11}' | head -1`
year=`echo "$nameFolder" | cut -d - -f 1`
month=`echo "$nameFolder" | cut -d - -f 2`
day=`echo "$nameFolder" | cut -d - -f 3 | cut -d _ -f 1`
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
	mkdir -p "$nameFolder"_"$ip"_"$1"_"$2"_folder
	mv "$nameFolder".pcap "$nameFolder"_"$ip"_"$1"_"$2"_folder/"$nameFolder"_"$ip"_"$1"_"$2".pcap
	mv "$nameFolder"_strip.pcap "$nameFolder"_"$ip"_"$1"_"$2"_folder/"$nameFolder"_"$ip"_"$1"_"$2"_strip.pcap
	mv "$nameFolder"_ss.txt "$nameFolder"_"$ip"_"$1"_"$2"_folder/"$nameFolder"_"$ip"_"$1"_"$2"_ss.txt
	mv output* "$nameFolder"_"$ip"_"$1"_"$2"_folder/
	nameModel=`ls ../maril-in-monroe-Model-based/"$year"/"$month"/"$day"/*serverdata | tail -1 | cut -d . -f 4 | cut -d _ -f 1`
	cp ../maril-in-monroe-Model-based/"$year"/"$month"/"$day"/*"$nameModel"* "$nameFolder"_"$ip"_"$1"_"$2"_folder/
else
	nameFail=`ls | grep '\.pcap' |sed 's/\.pcap//'`
	editcap -C 122:1420 "$nameFail".pcap "$nameFail"_strip.pcap
        chmod 777 "$nameFail"_strip.pcap
        mkdir -p "$nameFail"_"$1"_"$2"_FailedFolder
        mv "$nameFail".pcap "$nameFail"_"$1"_"$2"_FailedFolder/"$nameFail"_"$1"_"$2".pcap
	mv "$nameFail"_strip.pcap "$nameFail"_"$1"_"$2"_FailedFolder/"$nameFail"_"$1"_"$2"_strip.pcap
        mv "$nameFail"_ss.txt "$nameFail"_"$1"_"$2"_FailedFolder/"$nameFail"_"$1"_"$2"_ss.txt
	nameModel=`ls ../maril-in-monroe-Model-based/"$year"/"$month"/"$day"/*serverdata | tail -1 | cut -d . -f 4 | cut -d _ -f 1`
	cp ../maril-in-monroe-Model-based/"$year"/"$month"/"$day"/*"$nameModel"* "$nameFail"_"$1"_"$2"_FailedFolder/
fi
