
#include "actors/solid.h"
#include "assets/archive.h"

Solid::Solid(App *app, ActorInfo *info) : Actor(app, info) {
    texture = archive->texture(info->texture);
}

void Solid::update() {
    if (info->param && gamestate->flags == 5) {
        destroy();
    }
}

void Solid::draw(Painter *painter) {
    for (int x = 0; x < info->w; x++) {
        for (int y = 0; y < info->h; y++) {
            texture->draw(painter, position.x + x * 16 - camera->x, position.y + y * 16 - camera->y);
        }
    }
}

Collider *Solid::create_collider() {
    Collider *collider = new Collider(this, info->w * 16, info->h * 16);
    collider->passive = true;
    return collider;
}
