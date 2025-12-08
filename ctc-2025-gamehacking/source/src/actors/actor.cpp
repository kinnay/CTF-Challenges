
#include "actors/actor.h"

#include "app.h"


Actor::Actor(App *app, ActorInfo *info) {
    this->app = app;
    this->info = info;

    archive = app->archive;
    actorlist = app->actorlist;
    collisionmgr = app->collisionmgr;
    inputmgr = app->inputmgr;
    audioplayer = app->audioplayer;
    camera = app->camera;
    level = app->level;
    gamestate = app->gamestate;

    type = info->type;

    collider = nullptr;

    actorlist->add(this);
}

Actor::~Actor() {
    if (collider) {
        collisionmgr->remove(collider);
        delete collider;
    }
    if (!info->global) {
        delete info;
    }
}

void Actor::init() {
    collider = create_collider();
    if (collider) {
        collisionmgr->add(collider);
    }
}

void Actor::destroy() {
    actorlist->destroy(this);
}

void Actor::update() {}

void Actor::draw(Painter *painter) {}
void Actor::draw_foreground(Painter *painter) {}

Collider *Actor::create_collider() { return nullptr; }
void Actor::handle_collision(Actor *other, Collider::Side side) {}
