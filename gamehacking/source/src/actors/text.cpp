
#include "actors/text.h"
#include "assets/archive.h"

Text::Text(App *app, ActorInfo *info) : Actor(app, info) {
    font = archive->font(info->texture);
}

void Text::draw(Painter *painter) {
    font->draw(painter, position.x - camera->x, position.y - camera->y, info->text);
}
