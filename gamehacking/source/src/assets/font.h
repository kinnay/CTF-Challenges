
#pragma once

#include "assets/spritesheet.h"
#include "assets/stream.h"
#include "system/painter.h"

#include <string>

class Archive;

class Font {
public:
    Font(Stream *stream, Archive *archive);

    void draw(Painter *painter, int x, int y, const std::string &text);

private:
    SpriteSheet *spritesheet;
    std::string chars;
};
