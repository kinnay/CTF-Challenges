
#pragma once

#include "actors/actor.h"
#include "assets/texture.h"
#include "physics/collider.h"

class Trophy : public Actor {
public:
    Trophy(App *app, ActorInfo *info);

    void update();
    void draw(Painter *painter);
    Collider *create_collider();

    void hit();

private:
    Texture *texture;

    bool hit_flag;
    bool hit_active;
};
