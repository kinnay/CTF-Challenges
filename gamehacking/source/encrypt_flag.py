
from Crypto.Cipher import ARC4

import struct

def rol(value, bits):
	return ((value << bits) | (value >> (32 - bits))) & 0xFFFFFFFF

class SHA1:
	def __init__(self):
		self.h0 = 0
		self.h1 = 1
		self.h2 = 2
		self.h3 = 3
		self.h4 = 4
	
	def update(self, data):
		w = [0] * 80
		w[:16] = struct.unpack("<16I", data)
		for i in range(16, 80):
			w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
		
		a, b, c, d, e = self.h0, self.h1, self.h2, self.h3, self.h4
		for i in range(80):
			if i < 20:
				f = (b & c) | (~b & d)
				k = 0x5A827999
			elif i < 40:
				f = b ^ c ^ d
				k = 0x6ED9EBA1
			elif i < 60:
				f = (b & c) | (b & d) | (c & d)
				k = 0x8F1BBCDC
			else:
				f = b ^ c ^ d
				k = 0xCA62C1D6
			
			temp = (rol(a, 5) + f + e + k + w[i]) & 0xFFFFFFFF
			e = d
			d = c
			c = rol(b, 30)
			b = a
			a = temp
		
		self.h0 = (self.h0 + a) & 0xFFFFFFFF
		self.h1 = (self.h1 + b) & 0xFFFFFFFF
		self.h2 = (self.h2 + c) & 0xFFFFFFFF
		self.h3 = (self.h3 + d) & 0xFFFFFFFF
		self.h4 = (self.h4 + e) & 0xFFFFFFFF

words = ["grass/topleft", "grass/top", "grass/topright", "grass/center", "items/apple"]

key = [0] * 256
for i in range(5):
	word = words[i].encode()
	for j in range(len(word)):
		key[i * 20 + j] = (word[j] * (7 + j * 15 + i * 31)) % 256

print(key)

key = bytes(key)

sha = SHA1()
sha.update(key[192:])
sha.update(key[64:128])
sha.update(key[128:192])
sha.update(key[:64])

print(sha.h0)
print(sha.h1)
print(sha.h2)
print(sha.h3)
print(sha.h4)

key = struct.pack("<4I", sha.h0, sha.h1, sha.h2, sha.h3)
rc4 = ARC4.new(key)

text = """CONGRATS! HERE IS THE FLAG:

CTF(MEM0RY-HACK1NG-W38A5SEMB1Y-G4ME5)"""

encrypted = rc4.encrypt(text.encode())
print(", ".join(str(i) for i in encrypted))
