#!/bin/bash
sudo tcpreplay -i wlan0 ./sample_packets/*a2000ua*.pcap
sudo tcpreplay -i wlan0 ./sample_packets/*awus051nh*.pcap
sudo tcpreplay -i wlan0 ./sample_packets/*galaxy7*.pcap
sudo tcpreplay -i wlan0 ./sample_packets/*a2000ua*.pcap
sudo tcpreplay -i wlan0 ./sample_packets/*nexus5*.pcap
sudo tcpreplay -i wlan0 ./sample_packets/*forcerecon*.pcap
sudo tcpreplay -i wlan0 ./sample_packets/*dot11*.pcap
sudo tcpreplay -i wlan0 ./sample_packets/80211-icmp.pcap
sudo tcpreplay -i wlan0 ./sample_packets/80211-sample2.pcap
sudo tcpreplay -i wlan0 ./sample_packets/80211-sample.pcap
sudo tcpreplay -i wlan0 ./sample_packets/80211-sample1.pcap
sudo tcpreplay -i wlan0 ./sample_packets/80211-sample3.pcap