
#include "assets/spritesheet.h"
#include "assets/archive.h"

SpriteSheet::SpriteSheet(Stream *stream, Archive *archive) {
    texture = archive->texture(stream->string());
    width = stream->u8();
    height = stream->u8();
}

void SpriteSheet::draw(Painter *painter, int x, int y, int index, bool flipped) {
    int span = texture->width / width;
    int sx = index % span * width;
    int sy = index / span * height;

    texture->draw(painter, x, y, sx, sy, width, height, flipped);
}
