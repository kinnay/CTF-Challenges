
#include "rc4.h"

void swap(uint8_t *a, uint8_t *b) {
	uint8_t temp = *a;
	*a = *b;
	*b = temp;
}

void RC4::setkey(uint8_t *key, size_t length) {
	x = y = 0;
	for (int i = 0; i < 256; i++) {
		state[i] = i;
	}

	uint8_t p = 0;
	for (int i = 0; i < 256; i++) {
		p += state[i] + key[i % length];
		swap(state + i, state + p);
	}
}

void RC4::decrypt(uint8_t *data, size_t length) {
	for (size_t i = 0; i < length; i++) {
		x += 1;
		y += state[x];
		swap(state + x, state + y);
		data[i] ^= state[(state[x] + state[y]) % 256];
	}
}
