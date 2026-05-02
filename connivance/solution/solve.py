
import hashlib

with open("dragonfly.bin", "rb") as f:
	data = f.read()

template = b"dach2026{...................}"

flag = [0] * 29
for i in range(8):
	flag = [x << 1 for x in flag]
	target = data[i * 32 : (i + 1) * 32]

	for k in [0, 1, 2, 3, 4, 5, 6, 7, 8, 28]:
		if not template[k] & (1 << (7 - i)):
			flag[k] |= 1
	
	for j in range(2 ** 19):
		for k in range(19):
			if j & (1 << k):
				flag[k+9] |= 1
			else:
				flag[k+9] &= ~1
		if hashlib.sha256(bytes(flag)).digest() == target:
			break
	else:
		raise ValueError("Could not find bits that generate the hash")

flag = [x ^ 0xFF for x in flag]
print(bytes(flag).decode())
