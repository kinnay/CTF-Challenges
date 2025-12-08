
#pragma once

#include "actors/actor.h"
#include "assets/texture.h"
#include "physics/collider.h"

class SolidOnTop : public Actor {
public:
    SolidOnTop(App *app, ActorInfo *info);

    void update();
    void draw(Painter *painter);

    Collider *create_collider();

private:
    Texture *texture;
};
