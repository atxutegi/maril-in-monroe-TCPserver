#!/bin/sh
#sudo ethtool -K eth0 tso off
#sudo ethtool -K eth0 gro off
#sudo ethtool -K eth0 gso off
#sudo ethtool -K eth0 tso on && sudo ethtool -K eth0 gro on && sudo ethtool -K eth0 gso on

sudo sysctl -w net.ipv4.tcp_no_metrics_save=1 #no TCP record of previous connections whatsoever
sudo /sbin/modprobe tcp_hybla
sudo /sbin/modprobe tcp_westwood
sudo /sbin/modprobe tcp_illinois
sudo /sbin/modprobe tcp_yeah
sudo sysctl -w net.ipv4.tcp_allowed_congestion_control="cubic reno hybla westwood illinois yeah"
sudo sysctl -w net.ipv4.tcp_available_congestion_control="cubic reno hybla westwood illinois yeah"
