
#include "common/endian.h"

uint8_t Endian::swap8(uint8_t value) { return value; }
uint16_t Endian::swap16(uint16_t value) { return (value << 8) | (value >> 8); }
uint32_t Endian::swap32(uint32_t value) {
	return (swap16(value & 0xFFFF) << 16) | swap16(value >> 16);
}
uint64_t Endian::swap64(uint64_t value) {
	return ((uint64_t)swap32(value & 0xFFFFFFFF) << 32) | swap32(value >> 32);
}

template <> void Endian::swap<1>(void *value) {}
template <> void Endian::swap<2>(void *value) {
	*(uint16_t *)value = swap16(*(uint16_t *)value);
}
template <> void Endian::swap<4>(void *value) {
	*(uint32_t *)value = swap32(*(uint32_t *)value);
}
template <> void Endian::swap<8>(void *value) {
	*(uint64_t *)value = swap64(*(uint64_t *)value);
}