#!/bin/bash
sudo modprobe mac80211_hwsim [radios=1]
sudo ifconfig wlan0 down;
sudo iwconfig wlan0 mode monitor;
sudo ifconfig wlan0 up;