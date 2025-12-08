
from Crypto.Cipher import ARC4
from flask import Flask, request

from dataclasses import dataclass

import hashlib
import hmac
import os
import random
import secrets
import string
import struct
import time


FLAG = os.environ.get("FLAG", "CSCG{testflag}")


@dataclass
class Principal:
	name: str
	password: str


app = Flask(__name__)

principals = {}
principals["Administrator"] = Principal("Administrator", secrets.token_urlsafe(16))
principals["Flag Service"] = Principal("Flag Service", secrets.token_urlsafe(16))
principals["Test Service"] = Principal("Test Service", secrets.token_urlsafe(16))


def error(message):
	return {"error": message}, 400

def encrypt(plaintext, key):
	# Encrypt then digest
	ciphertext = ARC4.new(key).encrypt(plaintext)
	signature = hmac.digest(key, ciphertext, "sha256")
	return ciphertext + signature

def decrypt(ciphertext, key):
	# Verify then decrypt
	signature = hmac.digest(key, ciphertext[:-32], "sha256")
	if signature != ciphertext[-32:]:
		raise ValueError("HMAC is incorrect")
	return ARC4.new(key).decrypt(ciphertext[:-32])

def derive_key(password):
	# Derive a key from the given password
	return hashlib.sha256(password.encode()).digest()

def generate_nonce(length):
	# Generate a random nonce of the given length
	return bytes(random.getrandbits(32) & 0xFF for i in range(length))

def generate_ticket(user, service):
	# Generate a ticket that allows the user principal
	# to authenticate on the given service principal
	timestamp = int(time.time())

	ticket = struct.pack("<Q", timestamp)
	ticket += user.name.encode().ljust(16, b"\0")

	nonce = generate_nonce(16)
	service_key = derive_key(service.password)
	modified_key = hashlib.sha256(service_key + nonce).digest()
	return nonce + encrypt(ticket, modified_key)

def generate_ticket_response(user, service):
	# Generate a ticket and encrypt it with the user's password
	ticket = generate_ticket(user, service)

	user_key = derive_key(user.password)
	return encrypt(ticket, user_key)

def validate_ticket(service, ticket):
	# Check whether the ticket is valid for the given service
	# principal and extract the user from the ticket
	nonce = ticket[:16]
	service_key = derive_key(service.password)
	modified_key = hashlib.sha256(service_key + nonce).digest()

	plaintext = decrypt(ticket[16:], modified_key)
	timestamp = struct.unpack_from("<Q", plaintext)[0]
	username = plaintext[8:24].rstrip(b"\0").decode()

	if int(time.time()) > timestamp + 300:
		raise ValueError("Ticket has expired")
	if username not in principals:
		raise ValueError("User principal does not exist")
	
	return principals[username]


@app.get("/")
def index():
	return """
		<style>* { font-family: monospace }</style>

		Please use one of the following APIs:<br>
		<ul>
			<li>/api/register</li>
			<li>/api/request_ticket</li>
			<li>/api/authenticate</li>
		</ul>
	"""

@app.post("/api/register")
def register():
	# Register a new principal if it does not exist already
	name = str(request.json.get("name", ""))
	password = str(request.json.get("password", ""))

	if len(name) > 16 or any(char not in string.printable for char in name):
		return error("Principal name is invalid.")
	
	if name in principals:
		return error("Principal already exists.")
	
	principals[name] = Principal(name, password)
	return {}

@app.post("/api/request_ticket")
def request_ticket():
	# Request a ticket that allows the given user principal to authenticate
	# on the given service principal. The response is encrypted with the
	# user's password.
	user = str(request.json.get("user", ""))
	service = str(request.json.get("service", ""))

	if user not in principals:
		return error("User principal not found.")
	if service not in principals:
		return error("Service principal not found.")
	
	user = principals[user]
	service = principals[service]

	ticket = generate_ticket_response(user, service)
	return {"ticket": ticket.hex()}

@app.post("/api/authenticate")
def authenticate():
	service = str(request.json.get("service", ""))
	ticket = str(request.json.get("ticket", ""))

	if service not in principals:
		return error("Service principal not found.")
	
	service = principals[service]

	try:
		user = validate_ticket(service, bytes.fromhex(ticket))
	except ValueError:
		return error("Ticket is invalid.")
	
	response = {}
	if service.name == "Flag Service":
		if user.name != "Administrator":
			return error("Only Administrator may access the flag service!")
		response["flag"] = FLAG
	return response
