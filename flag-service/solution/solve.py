
from Crypto.Cipher import ARC4

import gzip
import hashlib
import hmac
import pickle
import rebuild_random
import requests
import struct
import time

BASE = "http://localhost:8000"

def encrypt(plaintext, key):
	ciphertext = ARC4.new(key).encrypt(plaintext)
	signature = hmac.digest(key, ciphertext, "sha256")
	return ciphertext + signature

def decrypt(ciphertext, key):
	signature = hmac.digest(key, ciphertext[:-32], "sha256")
	if signature != ciphertext[-32:]:
		raise ValueError("HMAC is incorrect")
	return ARC4.new(key).decrypt(ciphertext[:-32])

def derive_key(password):
	return hashlib.sha256(password.encode()).digest()

def generate_key(random, length):
	return bytes(random.getrandbits(32) & 0xFF for i in range(length))

def xor(a, b):
	return bytes(p ^ q for p, q in zip(a, b))

def register(name, password):
	data = {
		"name": name,
		"password": password
	}
	requests.post(BASE + "/api/register", json=data)

def request_ticket(user, service):
	data = {
		"user": user,
		"service": service
	}
	r = requests.post(BASE + "/api/request_ticket", json=data)
	return bytes.fromhex(r.json()["ticket"])

def authenticate(service, ticket):
	data = {
		"service": service,
		"ticket": ticket.hex()
	}
	r = requests.post(BASE + "/api/authenticate", json=data)
	return r.json()

# Register an account with a known password
register("test", "test")

# Request enough tickets to recover the RNG state
output = b""
while len(output) < 3739:
	ticket = request_ticket("test", "test")
	ticket = decrypt(ticket, derive_key("test"))
	output += ticket[:16]

# This was generated with not_random (see solution.txt)
f = gzip.GzipFile("magic_data_8")
magic = pickle.load(f)
f.close()

# Recover the RNG state from the nonces
random = rebuild_random.rebuild_random(magic, output)
assert generate_key(random, len(output)) == output

# Request a ticket for Administrator for a service with a known password
ticket = request_ticket("Administrator", "test")

# Predict the content of the ticket and recover the keystream of Administrator
nonce = generate_key(random, 16)
key = hashlib.sha256(derive_key("test") + nonce).digest()
content = struct.pack("<Q", int(time.time()))
content += b"Administrator\0\0\0"
keystream = xor(ticket, nonce + encrypt(content, key))

# Request a ticket for the Flag Service and decrypt the response
ticket = request_ticket("Administrator", "Flag Service")
ticket = xor(ticket, keystream)

# Profit!
print(authenticate("Flag Service", ticket))
