
#pragma once

#include "actors/actor.h"
#include "assets/texture.h"
#include "physics/collider.h"

class Spikes : public Actor {
public:
    Spikes(App *app, ActorInfo *info);

    void draw(Painter *painter);

    Collider *create_collider();

private:
    Texture *texture;
};
