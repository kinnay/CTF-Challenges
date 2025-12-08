
#include "actors/item.h"
#include "assets/archive.h"

Item::Item(App *app, ActorInfo *info) : Actor(app, info) {
    sprite = archive->sprite(info->texture);
    animation_frame = 0;
}

void Item::update() {
    animation_frame++;
}

void Item::draw(Painter *painter) {
    sprite->draw(painter, position.x - camera->x, position.y - camera->y, animation_frame);
}

Collider *Item::create_collider() {
    Collider *collider = new Collider(this, 10, 10, 12, 12);
    collider->passive = true;
    return collider;
}
