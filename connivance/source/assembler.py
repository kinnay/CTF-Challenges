
from Crypto.Cipher import AES
import hashlib
import struct
import sys


OPCODES = {
	"invert_buffer": 1,
	"push_buffer_size": 13,
	"push_input": 30,
	"concat": 57,
	"write_output": 59,
	"sha256": 66,
	"load_file": 79,
	"rshift_bytes": 81,
	"new_buffer": 91,
	"load_whole_file": 94
}

OPCODES64 = {
	"pop_var": 21,
	"append_buffer": 25,
	"push_value": 29,
	"decrypt_program": 40,
	"push_var": 75
}

OPCODES6432 = {
	"compare": 23
}

OPCODES_LABEL = {
	"jump_if_eq": 28,
	"jump_if_ne": 47,
	"jump": 64
}

def encrypt(data, param):
	source = struct.pack("<Q", param)
	key = hashlib.sha256(source).digest()[:16]
	nonce = struct.pack(">Q", 0x2AF06007DD731AAC)
	aes = AES.new(key, AES.MODE_CTR, nonce=nonce)
	return aes.encrypt(data)

def assemble(text):
	labels = {}
	refs = {}
	encryptions = []

	lines = text.splitlines()

	offset = 0
	data = b""
	for line in lines:
		line = line.split("#")[0].strip()
		if line.endswith(":"):
			labels[line[:-1]] = offset
		elif line:
			mnem = line.split()[0]
			param32 = 0
			param64 = 0
			if mnem in OPCODES:
				opcode = OPCODES[mnem]
			elif mnem in OPCODES64:
				opcode = OPCODES64[mnem]
				param64 = eval(line.split(maxsplit=1)[1])
				if isinstance(param64, str):
					param64 = struct.unpack("<Q", bytes([ord(c) for c in param64]))[0]
				if mnem == "decrypt_program":
					encryptions.append((offset, param64))
			elif mnem in OPCODES6432:
				opcode = OPCODES6432[mnem]
				param64 = eval(line.split()[1])
				param32 = eval(line.split()[2])
			elif mnem in OPCODES_LABEL:
				opcode = OPCODES_LABEL[mnem]
				refs[offset] = line.split()[1]
			else:
				raise ValueError(f"Unknown mnemonic: {mnem}")

			data += struct.pack("<HxxIQ", opcode, param32, param64)
			offset += 1
	
	for offset, label in refs.items():
		target = labels[label]
		data = data[:offset*16+8] + struct.pack("<q", target - offset) + data[offset*16+16:]
	
	for offset, param in reversed(encryptions):
		data = data[:(offset + 1) * 16] + encrypt(data[(offset + 1) * 16:], param)

	return data

def assemble_file(filename):
	with open(filename) as f:
		text = f.read()
	return assemble(text)

def main():
	if len(sys.argv) < 3:
		print("Usage: python3 assembler.py <input> <output>")
		return
	
	data = assemble_file(sys.argv[1])

	with open(sys.argv[2], "wb") as f:
		f.write(data)

if __name__ == "__main__":
	main()
