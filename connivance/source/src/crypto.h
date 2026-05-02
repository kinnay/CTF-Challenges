
#pragma once

#include <cstddef>
#include <cstdint>


void decrypt_aes_ecb(uint8_t *buffer, size_t size, const uint8_t *key);

void decrypt_aes_ctr(
	uint8_t *buffer, size_t size, const uint8_t *key, uint64_t nonce
);

size_t decrypt_rsa_oaep(
	uint8_t *buffer, const uint8_t *public_key, const uint8_t *private_key
);

bool verify_signature(
	const uint8_t *buffer, size_t size, const uint8_t *signature,
	const uint8_t *public_key
);

bool verify_standard_signature(
	const uint8_t *buffer, size_t size, const uint8_t *signature
);
