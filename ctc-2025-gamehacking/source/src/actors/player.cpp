
#include "actors/block.h"
#include "actors/flag.h"
#include "actors/player.h"
#include "actors/trophy.h"
#include "assets/archive.h"
#include "app.h"

#include <algorithm>
#include <cmath>


Player::Player(App *app, ActorInfo *info) : Actor(app, info) {
    appear_sprite = archive->sprite("player/appear");
    idle_sprite = archive->sprite("player/idle");
    walking_sprite = archive->sprite("player/walk");
    jumping_sprite = archive->sprite("player/jump");

    jump_sound = archive->sound("jump");

    active_sprite = nullptr;

    appearing = true;
    grounded = false;
    walking = false;
    jumping = false;
    flying = false;

    flipped = false;

    animation_frame = 0;
}

void Player::update() {
    update_position();

    if (appearing) {
        animation_frame++;
        if (animation_frame == 21) {
            appearing = false;
        }
        return;
    }

    update_speed();

    if (speed.x > 0) flipped = false;
    else if (speed.x < 0) flipped = true;

    walking = false;
    if (grounded && speed.y >= 0) {
        jumping = flying = false;
        walking = speed.x != 0;
        if (inputmgr->pressed[Key_x] || inputmgr->pressed[Key_Up]) {
            jump_sound->play(audioplayer, 1);

            speed.y = -6.5;
            jumping = flying = true;
        }
    }
    else {
        update_air();
    }

    grounded = false;

    animation_frame++;
}

void Player::update_position() {
    // Cheats
    // if (inputmgr->pressed[Key_q]) position.x -= 80;
    // if (inputmgr->pressed[Key_w]) position.x += 80;
    // if (inputmgr->pressed[Key_e]) position.y -= 80;
    // if (inputmgr->pressed[Key_a]) gamestate->score += 100000;
    // if (inputmgr->hold[Key_s]) speed.y = speed.x = 0;

    position += speed;

    double offset = position.x - camera->x;
    if (offset < 180) {
        camera->x = std::max<double>(position.x - 180, level->min_x);
    }
    else if (offset > 300) {
        camera->x = std::min<double>(position.x - 300, level->max_x);
    }

    if (position.y - camera->y > 360) {
        app->die();
    }
}

void Player::update_speed() {
    bool running = inputmgr->hold[Key_z];

    double accel = .5;
    double decel = .25;
    double limit = running ? 3.5 : 1.75;
    if (inputmgr->hold[Key_Right] && !inputmgr->hold[Key_Left]) {
        speed.x = std::min(speed.x + accel, limit);
    }
    else if (inputmgr->hold[Key_Left] && !inputmgr->hold[Key_Right]) {
        speed.x = std::max(speed.x - accel, -limit);
    }
    else {
        if (speed.x < 0) {
            speed.x = std::min(.0, speed.x + decel);
        }
        else {
            speed.x = std::max(.0, speed.x - decel);
        }
    }
}

void Player::update_air() {
    if ((!inputmgr->hold[Key_x] && !inputmgr->hold[Key_Up]) || speed.y >= 0) {
        flying = false;
    }

    double gravity = flying ? .25 : .5;
    speed.y = std::min(speed.y + gravity, 8.);
}

void Player::draw_foreground(Painter *painter) {
    if (appearing) {
        appear_sprite->draw(painter, position.x - camera->x - 32, position.y - camera->y - 32, animation_frame);
        return;
    }

    Sprite *sprite;
    if (walking) sprite = walking_sprite;
    else if (jumping) sprite = jumping_sprite;
    else {
        sprite = idle_sprite;
    }

    if (sprite != active_sprite) {
        active_sprite = sprite;
        animation_frame = 0;
    }

    sprite->draw(painter, position.x - camera->x, position.y - camera->y, animation_frame, flipped);
}

Collider *Player::create_collider() {
    return new Collider(this, 6, 9, 20, 22);
}

void Player::handle_collision(Actor *other, Collider::Side side) {
    if (appearing) return;

    if (other->type == ActorType::Solid || other->type == ActorType::Block) {
        if (side == Collider::Left) {
            collider->move_left(other->collider->right());
            speed.x = std::max(speed.x, .0);
        }
        else if (side == Collider::Right) {
            collider->move_right(other->collider->left());
            speed.x = std::min(speed.x, .0);
        }
        else if (side == Collider::Bottom) {
            collider->move_bottom(other->collider->top());
            speed.y = std::min(speed.y, .0);
            grounded = true;
        }
        else if (side == Collider::Top) {
            collider->move_top(other->collider->bottom());
            speed.y = std::max(speed.y, .0);

            if (other->type == ActorType::Block) {
                Block *block = (Block *)other;
                block->hit();
            }
        }
    }
    else if (other->type == ActorType::SolidOnTop) {
        if (side == Collider::Bottom && speed.y >= 0 && position.y + 31 <= other->position.y + speed.y) {
            collider->move_bottom(other->collider->top());
            speed.y = 0;
            grounded = true;
        }
    }
    else if (other->type == ActorType::Item) {
        ActorInfo *effect = new ActorInfo();
        effect->type = ActorType::Effect;
        effect->x = other->position.x;
        effect->y = other->position.y;
        effect->texture = "items/collected";
        effect->param = 18;

        app->create_actor(effect);

        gamestate->score += 100;
        other->destroy();
    }
    else if (other->type == ActorType::Spikes) {
        app->die();
    }
    else if (other->type == ActorType::Flag) {
        Flag *flag = (Flag *)other;
        flag->hit();
    }
    else if (other->type == ActorType::Trophy) {
        Trophy *trophy = (Trophy *)other;
        trophy->hit();
    }
}
