
#include "actors/effect.h"
#include "assets/archive.h"

Effect::Effect(App *app, ActorInfo *info) : Actor(app, info) {
    sprite = archive->sprite(info->texture);
    animation_frame = 0;
}

void Effect::update() {
    animation_frame++;
    if (animation_frame == info->param) {
        destroy();
    }
}

void Effect::draw(Painter *painter) {
    sprite->draw(painter, position.x - camera->x, position.y - camera->y, animation_frame);
}
