
#include "actors/trophy.h"
#include "assets/archive.h"
#include "app.h"

Trophy::Trophy(App *app, ActorInfo *info) : Actor(app, info) {
    texture = archive->texture("trophy");

    hit_flag = false;
    hit_active = false;
}

void Trophy::update() {
    if (!hit_flag) {
        hit_active = false;
    }
    hit_flag = false;
}

void Trophy::draw(Painter *painter) {
    texture->draw(painter, position.x - camera->x, position.y - camera->y);
}

Collider *Trophy::create_collider() {
    Collider *collider = new Collider(this, 15, 21, 34, 43);
    collider->passive = true;
    return collider;
}

void Trophy::hit() {
    if (!hit_active) {
        app->trophy_collected();
    }

    hit_flag = true;
    hit_active = true;
}
