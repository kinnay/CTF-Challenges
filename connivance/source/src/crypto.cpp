
#include "crypto.h"

#include "common/endian.h"

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h>
#include <mbedtls/rsa.h>
#include <mbedtls/sha256.h>

void decrypt_aes_ecb(uint8_t *buffer, size_t size, const uint8_t *key) {
	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	mbedtls_aes_setkey_dec(&ctx, key, 16 * 8);
	for (size_t i = 0; i < size; i += 16) {
		mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, buffer + i, buffer + i);
	}
	mbedtls_aes_free(&ctx);
}

void decrypt_aes_ctr(uint8_t *buffer, size_t size, const uint8_t *key, uint64_t nonce) {
	size_t offset = 0;

	uint8_t nonce_counter[16] = {0};
	uint8_t stream_block[16] = {0};

	*(uint64_t *)(nonce_counter + 0) = Endian::swap64(nonce);

	mbedtls_aes_context ctx;
	mbedtls_aes_init(&ctx);
	mbedtls_aes_setkey_enc(&ctx, key, 16 * 8);
	mbedtls_aes_crypt_ctr(&ctx, size, &offset, nonce_counter, stream_block, buffer, buffer);
	mbedtls_aes_free(&ctx);
}

size_t decrypt_rsa_oaep(uint8_t *buffer, const uint8_t *public_key, const uint8_t *private_key) {
	uint8_t exponent[] = {1, 0, 1};

	mbedtls_entropy_context entropy;
	mbedtls_entropy_init(&entropy);

	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);

	mbedtls_rsa_context ctx;
	mbedtls_rsa_init(&ctx);
	mbedtls_rsa_set_padding(&ctx, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
	mbedtls_rsa_import_raw(&ctx, public_key, 256, 0, 0, 0, 0, private_key, 256, exponent, 3);
	mbedtls_rsa_complete(&ctx);

	size_t olen = 0;

	mbedtls_rsa_rsaes_oaep_decrypt(&ctx, mbedtls_ctr_drbg_random, &ctr_drbg, NULL, 0, &olen, buffer, buffer, 256);

	mbedtls_rsa_free(&ctx);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	return olen;
}

bool verify_signature(const uint8_t *buffer, size_t size, const uint8_t *signature, const uint8_t *public_key) {
	uint8_t exponent[] = {1, 0, 1};
	mbedtls_rsa_context ctx;
	mbedtls_rsa_init(&ctx);
	mbedtls_rsa_import_raw(&ctx, public_key, 256, 0, 0, 0, 0, 0, 0, exponent, 3);
	mbedtls_rsa_complete(&ctx);

	uint8_t hash[32];
	const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	mbedtls_md(info, buffer, size, hash);

	size_t hash_size = mbedtls_md_get_size(info);

	bool result = mbedtls_rsa_rsassa_pss_verify(&ctx, MBEDTLS_MD_SHA256, hash_size, hash, signature);

	mbedtls_rsa_free(&ctx);
	return result;
}

bool verify_standard_signature(const uint8_t *buffer, size_t size, const uint8_t *signature) {
	uint8_t hash[32];
	mbedtls_sha256(buffer, size, hash, false);
	return verify_signature(hash, 32, signature, (const uint8_t *)"\xda\xbb\xea\xcf\xbf\x66\xf6\xe2\xbc\xd8\xce\xa9\xcd\xf6\xba\x81\x19\x5e\x83\xa0\x4a\x58\x8d\xa6\x75\x6b\xb9\x9c\x3c\xfe\xeb\xbe\xf1\xb7\x4e\x90\xdc\xa4\x96\xc9\xf7\xda\x90\xbc\x77\x59\x3b\x2c\x63\x96\x6a\xdc\xfd\x10\x3c\x36\xa2\x0e\xb3\x60\x8f\x08\x0d\xea\xb9\xbf\x9d\xca\x8e\xbd\x0e\x4e\x31\x92\x32\x35\xea\x0e\xe4\x4b\xed\x79\x9a\x28\xc2\xa5\x3e\xf7\x5a\x23\xbc\x46\x68\x8f\xe3\xfe\x9e\x56\x75\x57\x17\x4b\xb1\x02\x37\xd0\x5e\xe0\xe5\x09\xc8\x2f\x99\x9e\x8c\x65\x6c\x91\x61\x8f\x5b\x68\x83\x36\x84\xbf\x9c\xd2\xa5\xa1\x92\xba\xcd\xbe\x55\x88\x28\x84\xe1\x6c\xc2\x9d\xf2\x61\x48\x83\x5b\x27\x74\x41\xce\x98\x5a\x2c\xcc\x19\x54\x46\xd5\x88\x6f\xfc\xb7\x1f\x8e\xe8\xd3\xb9\xcf\x43\x02\x00\xe9\x3e\xdd\x6e\x7b\x94\xe3\xf5\xa3\xb2\x5c\xc2\xc1\xa3\xf9\xc9\x67\x51\xf4\xaf\x9e\x5b\x92\x60\x8c\x09\xdf\x44\x7e\x8a\x54\x89\x00\xba\x11\x2e\x22\x3f\xcc\x0d\x93\x49\xad\x72\xc0\xe0\x59\x01\x5a\xed\x03\xbc\x63\x92\x12\x14\x66\x32\x24\x3b\x6f\xb2\xdf\xed\x73\x10\x9d\x5e\xaa\x26\x43\x86\x7f\x6a\x22\x4d\xcf\xbc\x0f\xb2\x83\x21\xc0\x9d");
}