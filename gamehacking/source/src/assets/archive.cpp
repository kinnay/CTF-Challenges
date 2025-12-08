
#include "assets/archive.h"

#include <format>
#include <ranges>
#include <stdexcept>

#include <cstdio>


Archive::Archive(const char *filename) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        throw std::runtime_error("Failed to open file");
    }

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    data = new uint8_t[size];;
    fread(data, 1, size, f);
    fclose(f);

    Stream stream(data, size);
    load(&stream);
}

Archive::~Archive() {
    delete[](data);
}

void Archive::load(Stream *stream) {
    textures.load(stream, this);
    spritesheets.load(stream, this);
    fonts.load(stream, this);
    sprites.load(stream, this);
    sounds.load(stream, this);
    levels.load(stream, this);
}

Texture *Archive::texture(const std::string &name) { return textures.get(name); }
SpriteSheet *Archive::spritesheet(const std::string &name) { return spritesheets.get(name); }
Font *Archive::font(const std::string &name) { return fonts.get(name); }
Sprite *Archive::sprite(const std::string &name) { return sprites.get(name); }
Sound *Archive::sound(const std::string &name) { return sounds.get(name); }
Level *Archive::level(const std::string &name) { return levels.get(name); }
