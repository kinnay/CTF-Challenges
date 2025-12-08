
#pragma once

#include "actors/actor.h"
#include "assets/sprite.h"
#include "physics/collider.h"

class Item : public Actor {
public:
    Item(App *app, ActorInfo *info);

    void update();
    void draw(Painter *painter);

    Collider *create_collider();

private:
    Sprite *sprite;
    int animation_frame;
};
