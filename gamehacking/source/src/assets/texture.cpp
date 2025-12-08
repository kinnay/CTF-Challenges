
#include "assets/texture.h"

Texture::Texture(Stream *stream, Archive *archive) {
    width = stream->u16();
    height = stream->u16();
    data = stream->read(width * height * 4);
    surface = new Surface(data, width, height);
}

Texture::~Texture() {
    delete surface;
}

void Texture::draw(Painter *painter, int x, int y, bool flipped) {
    painter->draw(surface, x, y, flipped);
}

void Texture::draw(Painter *painter, int sx, int sy, int w, int h, int dx, int dy, bool flipped) {
    painter->draw(surface, sx, sy, w, h, dx, dy, flipped);
}
