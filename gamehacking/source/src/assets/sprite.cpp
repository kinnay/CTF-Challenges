
#include "assets/sprite.h"
#include "assets/archive.h"

Sprite::Sprite(Stream *stream, Archive *archive) {
    spritesheet = archive->spritesheet(stream->string());

    size_t frames = stream->u8();
    for (size_t i = 0; i < frames; i++) {
        timings.push_back(stream->u8());
    }
    for (size_t i = 0; i < frames; i++) {
        indices.push_back(stream->u8());
    }

    loop = stream->u8();
}

void Sprite::draw(Painter *painter, int x, int y, int frame, bool flipped) {
    if (loop) {
        frame %= loop;        
    }

    int index = 0;
    for (size_t i = 0; i < timings.size(); i++) {
        if (frame >= timings[i]) {
            index = indices[i];
        }
    }

    spritesheet->draw(painter, x, y, index, flipped);
}
