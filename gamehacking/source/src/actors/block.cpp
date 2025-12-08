
#include "actors/block.h"
#include "assets/archive.h"
#include "app.h"

Block::Block(App *app, ActorInfo *info) : Actor(app, info) {
    texture = archive->texture("block");

    bump_timer = 0;
    bumping = false;

    flag = nullptr;
}

void Block::update() {
    // This is a bit hacky. The purpose is to ensure that the flag that is on
    // top of the message block at the left side of the level moves along with
    // the block when it is bumped.
    if (info->param && !flag) {
        for (Actor *actor : actorlist->actors) {
            if (actor->type == ActorType::Flag && actor->info->param == info->param) {
                flag = (Flag *)actor;
            }
        }
    }

    if (bumping) {
        if (bump_timer < 5) {
            bump_timer++;
            position.y -= 2;
            if (flag) {
                flag->position.y -= 2;
            }

            if (bump_timer == 4) {
                app->show_message(info->text);
            }
        }
        else if (bump_timer < 10) {
            bump_timer++;
            position.y += 2;
            if (flag) {
                flag->position.y += 2;
            }
        }
        else {
            bumping = false;
            bump_timer = 0;
        }
    }
}

void Block::draw(Painter *painter) {
    texture->draw(painter, position.x - camera->x, position.y - camera->y);
}

void Block::hit() {
    if (!bumping) {
        bumping = true;
    }
}

Collider *Block::create_collider() {
    Collider *collider = new Collider(this, 5, 3, 18, 18);
    collider->passive = true;
    return collider;
}
