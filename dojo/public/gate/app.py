
from Crypto.PublicKey import RSA
from flask import Flask, redirect, render_template, request
import base64
import jwt
import uuid


def encode(number):
	length = (number.bit_length() + 7) // 8
	data = number.to_bytes(length, "big")
	return base64.b64encode(data, b"-_").rstrip(b"=").decode()


app = Flask(__name__)

rsa = RSA.generate(2048)
private_key = rsa.export_key().decode()

jwks = [{
	"kty": "RSA",
	"e": encode(rsa.e),
	"n": encode(rsa.n),
	"alg": "RS256",
	"use": "sig",
	"kid": str(uuid.uuid4())
}]


@app.get("/jwks")
def keys():
	return jwks

@app.get("/")
def index():
	redirect_uri = request.args.get("redirect_uri", "")
	return render_template("index.html", redirect_uri=redirect_uri)

@app.post("/")
def token():
	name = request.form.get("name", "")
	redirect_uri = request.form.get("redirect_uri", "")

	headers = {
		"jku": "http://ctc2025-dojo-gate:8000/jwks",
		"kid": jwks[0]["kid"]
	}
	payload = {
		"name": name,
		"rank": "Ashigaru",
		"jti": str(uuid.uuid4())
	}
	token = jwt.encode(payload, private_key, "RS256", headers)
	return redirect(redirect_uri + "?token=" + token)
