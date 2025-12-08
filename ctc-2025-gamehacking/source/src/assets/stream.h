
#pragma once

#include <stdexcept>
#include <string>

#include <cstdint>

class Stream {
public:
    Stream(uint8_t *data, size_t size);

    uint8_t *read(size_t size);

    size_t available();
    size_t tell();

    uint8_t u8();
    uint16_t u16();
    uint32_t u32();

    int16_t s16();

    std::string string();

private:
    uint8_t *data;
    size_t size;
    size_t pos;
};
