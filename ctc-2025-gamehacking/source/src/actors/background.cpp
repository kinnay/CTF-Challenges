
#include "actors/background.h"
#include "assets/archive.h"

Background::Background(App *app, ActorInfo *info) : Actor(app, info) {
    texture = archive->texture(info->texture);
}

void Background::draw(Painter *painter) {
    for (int x = 0; x < info->w; x++) {
        for (int y = 0; y < info->h; y++) {
            texture->draw(painter, position.x + x * 16 - camera->x, position.y + y * 16 - camera->y);
        }
    }
}
