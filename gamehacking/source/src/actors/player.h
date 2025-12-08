
#pragma once

#include "actors/actor.h"
#include "assets/sound.h"
#include "assets/sprite.h"
#include "physics/collider.h"
#include "system/painter.h"

class App;

class Player : public Actor {
public:
    Player(App *app, ActorInfo *info);

    void update();
    void draw_foreground(Painter *painter);

    Collider *create_collider();
    void handle_collision(Actor *other, Collider::Side);

private:
    void update_position();
    void update_speed();
    void update_air();

    Sprite *appear_sprite;
    Sprite *idle_sprite;
    Sprite *walking_sprite;
    Sprite *jumping_sprite;
    Sprite *active_sprite;

    Sound *jump_sound;

    bool appearing;
    bool grounded;
    bool walking;
    bool jumping;
    bool flying;
    
    bool flipped;

    int animation_frame;
};
