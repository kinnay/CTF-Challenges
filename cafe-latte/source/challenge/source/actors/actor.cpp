
#include "actors/actor.h"

#include "app.h"


Actor::Actor(App *app) {
    this->app = app;

    loader = app->loader;
    actorlist = app->actorlist;
    inputmgr = app->inputmgr;
    gamestate = app->gamestate;

    pending_deletion = false;
}

Actor::~Actor() {
}

void Actor::init() {
}

void Actor::destroy() {
    if (!pending_deletion) {
        pending_deletion = true;
        actorlist->destroy(this);
    }
}

void Actor::update() {
    position += speed;
}

void Actor::draw() {}
