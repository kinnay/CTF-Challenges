
#include "stream.h"

Stream::Stream(uint8_t *data, size_t size) {
    this->data = data;
    this->size = size;
    this->pos = 0;
}

uint8_t *Stream::read(size_t size) {
    if (available() < size) {
        throw std::runtime_error("Buffer overflow");
    }
    uint8_t *result = data + pos;
    pos += size;
    return result;
}

size_t Stream::available() { return size - pos; }
size_t Stream::tell() { return pos; }

uint8_t Stream::u8() { return read(1)[0]; }
uint16_t Stream::u16() { return *(uint16_t *)read(2); }
uint32_t Stream::u32() { return *(uint32_t *)read(4); }

int16_t Stream::s16() { return *(int16_t *)read(2); }

std::string Stream::string() {
    size_t size = u8();
    return std::string((char *)read(size), size);
}
