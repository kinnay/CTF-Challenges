
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
import assembler
import hashlib
import secrets
import struct

class Builder:
	def __init__(self):
		self.blob = b""
		self.key = bytes([x ^ 0xFF for x in b'o\xee1\xb5\xef\x98H\x03c\xa2\xca\x91\xb9 o*'])
	
	def build(self, name):
		data = assembler.assemble_file(f"files/{name}.asm")
		key = secrets.token_bytes(16)

		rsa = RSA.generate(2048)
		pkcs1 = PKCS1_OAEP.new(rsa, SHA256)
		enckey = pkcs1.encrypt(key)

		aes = AES.new(self.key, AES.MODE_ECB)
		temp = rsa.d.to_bytes(256) + rsa.n.to_bytes(256)
		self.blob += aes.encrypt(temp)
		self.key = hashlib.sha256(self.key).digest()[:16]

		aes = AES.new(key, AES.MODE_ECB)
		cipher = aes.encrypt(data)

		output = b"TINFOIL\xF0"
		output += enckey
		output += struct.pack("<Q", len(data))
		output += cipher

		with open(f"chal/{name}.tfl", "wb") as f:
			f.write(output)
	
	def finish(self):
		with open("chal/romfs/blob", "wb") as f:
			f.write(self.blob)
		
		blob_hash = hashlib.sha256(self.blob).digest()
		blob_signature = signer.sign(SHA256.new(blob_hash))

		with open("chal/romfs/blob.sig", "wb") as f:
			f.write(blob_signature)


n = 27612615923623864781107935269791760381788527310900265614770991628260323413910588493734959066747039524685260211235886951514041615673576407279433477468350130419238169787007460529874491146158783339914956792587091667166955369881135661009148334902157030290232980471269785219808697693433344754939978017068352135561698549910233789211604603245164453681768240606696079949446392006437980877188763032097150761596046715132857367735732352067591032739531779445919473686305603164316757146249925366547742190795547307680575330162794579530251176763051699672074419805383529110984867887007375956541815936614933490143525680103019058938013
e = 65537
d = 1693951848893445662029761108262474214794402765666333794714234277452746239309512504982855530888757074766881130953108678892262451986139340303446332547438877265522484422977302822228060357555753061905917020684443933165154707487481970872747926827198717370063959259422008506282571205219170279189407229772850599829477588902374385368663282033273984067376146776518441684438163770732150197676147394937600401140590538034607835128939152614923380065041447103913364180853687217223381613238850990029353955322306925818284802886525523214815622242554248682350535081740824233351424329245796978982571779391789377808958214688663854079345

key = RSA.construct((n, e, d))
signer = pss.new(key)

with open("chal/main", "rb") as f:
	main = f.read()

text_offs = struct.unpack_from("<Q", main, 0xF0)[0]
text_size = struct.unpack_from("<Q", main, 0x108)[0]
rodata_offs = struct.unpack_from("<Q", main, 0x128)[0]
rodata_size = struct.unpack_from("<Q", main, 0x140)[0]

text = main[text_offs:text_offs+text_size]
rodata = main[rodata_offs:rodata_offs+rodata_size]

text_hash = hashlib.sha256(text).digest()
rodata_hash = hashlib.sha256(rodata).digest()

maps = struct.pack("<QQ", len(text), len(rodata))
maps += text_hash + rodata_hash

with open("chal/romfs/map", "wb") as f:
	f.write(maps)

text_signature = signer.sign(SHA256.new(text_hash))
rodata_signature = signer.sign(SHA256.new(rodata_hash))

with open("chal/romfs/damocles.bin", "wb") as f:
	f.write(text_signature + rodata_signature)

with open("chal/romfs/connivance.bin", "rb") as f:
	data = f.read()

key = hashlib.sha256(b"dilate").digest()[16:]
nonce = struct.pack(">Q", 4096)
aes = AES.new(key, AES.MODE_CTR, nonce=nonce)
program = aes.decrypt(data[256:])
program_hash = hashlib.sha256(program).digest()
program_signature = signer.sign(SHA256.new(program_hash))

with open("chal/romfs/connivance.bin", "wb") as f:
	f.write(program_signature + data[256:])

builder = Builder()
builder.build("hello_world")
builder.build("flag_checker")
builder.finish()

flag = "dach2026{lE3t_R3V3RSe_MAsTER}"
flag = bytes(x ^ 0xFF for x in flag.encode())

dragonfly = b""
for i in range(8):
	dragonfly = hashlib.sha256(flag).digest() + dragonfly
	flag = bytes(x >> 1 for x in flag)

with open("chal/romfs/dragonfly.bin", "wb") as f:
	f.write(dragonfly)
