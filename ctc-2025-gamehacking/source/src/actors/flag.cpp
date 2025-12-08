
#include "actors/flag.h"
#include "assets/archive.h"
#include "app.h"

Flag::Flag(App *app, ActorInfo *info) : Actor(app, info) {
    sprite_off = archive->texture("flag/off");
    sprite_collect = archive->sprite("flag/collect");
    sprite_on = archive->sprite("flag/on");

    state = Off;

    hit_flag = false;
    hit_active = false;

    animation_frame = 0;

    requires_score = (info->param == 3);
}

void Flag::update() {
    if (state == Off && requires_score && gamestate->score >= 1000000) {
        state = Collect;
    }

    if (state == Collect) {
        animation_frame++;
        if (animation_frame == 20 && requires_score) {
            if (gamestate->score < 1000000) {
                state = Off;
                animation_frame = 0;
            }
        }
        else if (animation_frame == 21) {
            gamestate->flags++;
            app->flag_collected(info->param, info->text);
        }
        else if (animation_frame == 52) {
            state = On;
            animation_frame = 0;
        }
    }
    else if (state == On) {
        animation_frame++;
    }

    if (!hit_flag) {
        hit_active = false;
    }
    hit_flag = false;
}

void Flag::draw(Painter *painter) {
    if (state == Off) {
        sprite_off->draw(painter, position.x - camera->x, position.y - camera->y);
    }
    else if (state == Collect) {
        sprite_collect->draw(painter, position.x - camera->x, position.y - camera->y, animation_frame);
    }
    else if (state == On) {
        sprite_on->draw(painter, position.x - camera->x, position.y - camera->y, animation_frame);
    }
}

void Flag::hit() {
    if (state == Off && !hit_active) {
        state = Collect;
        if (!requires_score) {
            gamestate->score += 1000;
        }
    }

    hit_flag = true;
    hit_active = true;
}

Collider *Flag::create_collider() {
    Collider *collider = new Collider(this, 20, 18, 7, 46);
    collider->passive = true;
    return collider;
}
