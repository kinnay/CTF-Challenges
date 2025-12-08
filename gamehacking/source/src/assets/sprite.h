
#pragma once

#include "assets/spritesheet.h"
#include "assets/stream.h"
#include "system/painter.h"

#include <vector>

class Archive;

class Sprite {
public:
    Sprite(Stream *stream, Archive *archive);

    void draw(Painter *painter, int x, int y, int frame, bool flipped = false);

private:
    SpriteSheet *spritesheet;
    std::vector<int> timings;
    std::vector<int> indices;
    int loop;
};
