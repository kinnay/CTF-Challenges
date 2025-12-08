
#pragma once

#include "actors/actor.h"
#include "assets/sprite.h"

class Effect : public Actor {
public:
    Effect(App *app, ActorInfo *info);

    void update();
    void draw(Painter *painter);

private:
    Sprite *sprite;
    int animation_frame;
};
