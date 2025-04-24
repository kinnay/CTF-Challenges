
from assembler import Assembler
import encoding
import json
import os
import puzzle
import struct


flag = b"AuRuM_fulmiN@N$_a825ec"

if not os.path.isdir("build"):
	os.mkdir("build")

padded = flag.ljust(22, b"\0")
solution = puzzle.gensolution()
mask = encoding.xor(padded, solution)
print("flag:", padded.hex())
print("mask:", mask.hex())
print("solu:", solution.hex())

key1 = mask[:16][::-1]
key2 = mask[16:][::-1]
print("key1:", key1.hex())
print("key2:", key2.hex())

with open("template/program.txt") as f:
	code = f.read()

print(puzzle.genpuzzle())

code = code.replace("$puzzle", puzzle.genpuzzle())
code = code.replace("$flagsize", str(len(flag)))
code = code.replace("$key1", "0x%s" %key1.hex())
code = code.replace("$key2", "0x%s" %key2.hex())

assembler = Assembler()
assembler.assemble(code)

with open("build/program.bin", "wb") as f:
	f.write(assembler.data)

data = assembler.data
values = []
while data:
	values.append(struct.unpack_from("<I", data)[0])
	data = data[4:]

with open("template/skullcode.js") as f:
	code = f.read()

code = code.replace("$values", json.dumps(values, separators=(",", ":")))

with open("build/skullcode.js", "w") as f:
	f.write(code)

data = encoding.encode(encoding.compress(code + "   "))

with open("template/wrapper.js") as f:
	wrapper = f.read()

wrapper = wrapper.replace("$program", data)

with open("challenge/js/skullcode.js", "w") as f:
	f.write(wrapper)
