#!/bin/sh
#i=0
#base=1
while true 
do 
	echo `date +%s%3N` >> "$2"_ss.txt 
	ssOut=`ss -ait | grep -A1 $1`
	echo $ssOut >> "$2"_ss.txt
	sleep 0.001
	clear 
	#i=$((i+base))
done
