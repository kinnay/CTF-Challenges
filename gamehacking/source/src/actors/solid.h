
#pragma once

#include "actors/actor.h"
#include "assets/texture.h"
#include "physics/collider.h"

class Solid : public Actor {
public:
    Solid(App *app, ActorInfo *info);

    void update();
    void draw(Painter *painter);

    Collider *create_collider();

private:
    Texture *texture;
};
