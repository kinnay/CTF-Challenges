
#pragma once

#include <cstddef>
#include <cstdint>

class RC4 {
public:
	void setkey(uint8_t *key, size_t length);
	void decrypt(uint8_t *data, size_t length);

	uint8_t x, y;
	uint8_t state[256];
};