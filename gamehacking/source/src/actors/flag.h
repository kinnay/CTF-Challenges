
#pragma once

#include "actors/actor.h"
#include "assets/sprite.h"
#include "assets/texture.h"
#include "physics/collider.h"

class Flag : public Actor {
public:
    enum State {
        Off,
        Collect,
        On
    };

    Flag(App *app, ActorInfo *info);

    void update();
    void draw(Painter *painter);

    void hit();

    Collider *create_collider();

private:
    Texture *sprite_off;
    Sprite *sprite_collect;
    Sprite *sprite_on;

    State state;
    int animation_frame;
    bool requires_score;

    bool hit_flag;
    bool hit_active;
};
