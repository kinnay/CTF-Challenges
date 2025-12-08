
#pragma once

#include "assets/stream.h"
#include "system/painter.h"
#include "system/surface.h"

class Archive;

class Texture {
public:
    Texture(Stream *stream, Archive *archive);
    ~Texture();

    void draw(Painter *painter, int x, int y, bool flipped = false);
    void draw(Painter *painter, int sx, int sy, int w, int h, int dx, int dy, bool flipped = false);

    int width;
    int height;

private:
    uint8_t *data;
    Surface *surface;
};
