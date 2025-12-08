
import streams
import string


def xor(a, b):
	return bytes(p ^ q for p, q in zip(a, b))

def compress(data):
	stream = streams.BitStreamOut("<")
	prev = ""
	while data:
		for i in range(35, 2, -1):
			if len(data) >= i and data[:i] in prev[-1026:]:
				pos = (len(data) - prev.index(data[:i], -1026)) - 3
				stream.bits(i - 3)
				stream.bits(pos, 10)
				data = data[i:]
				break
		else:
			stream.bits(ord(data[0]), 7)
			data = data[1:]
	return stream.get()

def encode(data):
	charset = string.digits + string.ascii_lowercase + string.ascii_uppercase + "-_"
	stream = streams.BitStreamIn(data, "<")
	output = ""
	while stream.size() * 8 - stream.tellbits() >= 6:
		value = stream.bits(6)
		output += charset[value]
	return output

def decode(data):
	charset = string.digits + string.ascii_lowercase + string.ascii_uppercase + "-_"
	
	stream = streams.BitStreamOut("<")
	for char in data:
		stream.bits(charset.index(char), 6)
	return stream.get()

def decompress(data):
	output = ""
	stream = streams.BitStreamIn(data, "<")
	while stream.size() * 8 - stream.tellbits() >= 7:
		value = stream.bits(7)
		if value < 32:
			if stream.size() * 8 - stream.tellbits() < 10:
				break
			pos = len(output) - stream.bits(10) - 3
			output += output[pos:pos+value+3]
		else:
			output += chr(value)
	return output
