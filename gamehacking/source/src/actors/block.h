
#pragma once

#include "actors/actor.h"
#include "actors/flag.h"
#include "assets/texture.h"
#include "physics/collider.h"

class Block : public Actor {
public:
    Block(App *app, ActorInfo *info);

    void update();
    void draw(Painter *painter);

    void hit();

    Collider *create_collider();

private:
    Texture *texture;

    bool bumping;
    int bump_timer;

    Flag *flag;
};
