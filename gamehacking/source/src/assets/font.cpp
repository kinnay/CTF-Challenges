
#include "assets/font.h"
#include "assets/archive.h"

Font::Font(Stream *stream, Archive *archive) {
    spritesheet = archive->spritesheet(stream->string());
    chars = stream->string();
}

void Font::draw(Painter *painter, int x, int y, const std::string &text) {
    for (size_t i = 0; i < text.size(); i++) {
        size_t index = chars.find(text[i]);
        spritesheet->draw(painter, x + i * spritesheet->width, y, index);
    }
}
