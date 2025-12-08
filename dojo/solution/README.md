
The flaw in this challenge is that the JWKs that are fetched from the JKU are stored in the same cache as the JTIs of revoked JWTs. This can be exploited as follows:

1. Send a POST request to `/gate/` with an arbitrary name. This returns a JWT with the "Ashigaru" rank.
2. Send a GET request to `/logout` with the token from step 1, so that its JTI ends up in the cache.
3. A token can now be forged by setting the `kid` field to `revoked-<jti>` and using the JTI as a symmetric key for signing.

This is implemented in `solve.py`.
