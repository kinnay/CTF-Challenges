
#pragma once

#include "assets/collection.h"
#include "assets/font.h"
#include "assets/level.h"
#include "assets/sound.h"
#include "assets/sprite.h"
#include "assets/spritesheet.h"
#include "assets/stream.h"
#include "assets/texture.h"

#include <map>
#include <string>


class Archive {
public:
    Archive(const char *filename);
    ~Archive();

    Texture *texture(const std::string &name);
    SpriteSheet *spritesheet(const std::string &name);
    Font *font(const std::string &name);
    Sprite *sprite(const std::string &name);
    Sound *sound(const std::string &name);
    Level *level(const std::string &name);

private:
    void load(Stream *stream);

    uint8_t *data;

    ResourceCollection<Texture> textures;
    ResourceCollection<SpriteSheet> spritesheets;
    ResourceCollection<Font> fonts;
    ResourceCollection<Sprite> sprites;
    ResourceCollection<Sound> sounds;
    ResourceCollection<Level> levels;
};
