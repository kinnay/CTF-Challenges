
#pragma once

#include "assets/stream.h"
#include "assets/texture.h"
#include "system/painter.h"

#include <vector>

class Archive;

class SpriteSheet {
public:
    SpriteSheet(Stream *stream, Archive *archive);

    void draw(Painter *painter, int x, int y, int index, bool flipped = false);

    int width;
    int height;

private:
    Texture *texture;
};
