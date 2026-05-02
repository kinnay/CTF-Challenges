
#pragma once

#include <cstdint>

class Endian {
public:
	enum Type {
		Little, Big
	};

	static uint8_t swap8(uint8_t);
	static uint16_t swap16(uint16_t);
	static uint32_t swap32(uint32_t);
	static uint64_t swap64(uint64_t);
	
	template <int N>
	static void swap(void *value);
	
	template <class T>
	static void swap(T *value) {
		swap<sizeof(T)>(value);
	}
};
