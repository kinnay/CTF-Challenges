
const express = require("express");
const jwt = require("jsonwebtoken");
const jwktopem = require("jwk-to-pem");
const cache = require("memory-cache");

async function fetch_public_key(jku, kid) {
	const response = await fetch(jku);
	const keys = await response.json();
	const key = keys.find(key => key.kid === kid);
	return jwktopem(key);
}

async function validate_token(token) {
	if (typeof token !== "string") {
		return;
	}

	try {
		const {header} = jwt.decode(token, {complete: true});

		if (header.jku !== "http://ctc2025-dojo-gate:8000/jwks"){
			return;
		}

		let public_key = cache.get(header.kid);
		if (!public_key) {
			public_key = await fetch_public_key(header.jku, header.kid);
			if (!public_key) {
				return;
			}
			cache.put(header.kid, public_key);
		}

		const payload = jwt.verify(token, public_key);
		if (is_token_revoked(payload.jti)) {
			return;
		}

		return payload;
	}
	catch (e) {
		return;
	}
}

async function revoke_token(token) {
	if (await validate_token(token)) {
		const payload = jwt.decode(token);
		const name = "revoked-" + payload.jti;
		cache.put(name, payload.jti);
	}
}

function is_token_revoked(jti) {
	const name = "revoked-" + jti;
	return cache.get(name);
}

const app = express();

app.set("view engine", "ejs");

app.use(express.static("static"));

app.get("/", (req, res) => {
	const gate_uri = "/gate/?redirect_uri=/dojo"
	return res.render("index", {gate_uri});
});

app.get("/dojo", async (req, res) => {
	const info = await validate_token(req.query.token);
	if (!info) {
		return res.redirect("/");
	}

	if (info.rank === "Samurai") {
		const flag = process.env.FLAG;
		return res.render("dojo-samurai", {flag})
	}

	const params = {
		name: info.name,
		token: req.query.token
	}
	return res.render("dojo-ashigaru", params);
})

app.get("/logout", async (req, res) => {
	await revoke_token(req.query.token);
	return res.redirect("/");
})

app.listen(3000, () => {
	console.log("Listening on http://0.0.0.0:3000/");
});
