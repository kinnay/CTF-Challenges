
#include "actors/spikes.h"
#include "assets/archive.h"

Spikes::Spikes(App *app, ActorInfo *info) : Actor(app, info) {
    texture = archive->texture("spikes");
}

void Spikes::draw(Painter *painter) {
    for (int x = 0; x < info->w; x++) {
        texture->draw(painter, position.x + x * 16 - camera->x, position.y - camera->y);
    }
}

Collider *Spikes::create_collider() {
    Collider *collider = new Collider(this, 0, 10, info->w * 16, 6);
    collider->passive = true;
    return collider;
}
