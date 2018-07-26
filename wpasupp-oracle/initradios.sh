#!/bin/bash
set -e

function setmonitor {
	ifconfig $1 down
	iw $1 set type monitor
	ifconfig $1 up
	iw $1 set channel $2

	# There seems to be a bug in some mac80211_hsim versions where channel is not
	# being set? Workaround: bring interface up/down after setting channel.
	ifconfig $1 down
	ifconfig $1 up
}

# Create the virtual interfaces
rmmod mac80211_hwsim 2> /dev/null || true
modprobe mac80211_hwsim radios=3
rfkill unblock wifi

setmonitor wlan2 1
