
#include "actors/actorlist.h"

ActorList::~ActorList() {
    reset();
}

void ActorList::reset() {
    for (Actor *actor : creations) { delete actor; }
    for (Actor *actor : actors) { delete actor; }
    
    creations.clear();
    deletions.clear();
    actors.clear();
}

void ActorList::add(Actor *actor) {
    creations.push_back(actor);
}

void ActorList::destroy(Actor *actor) {
    deletions.push_back(actor);
}

void ActorList::update() {
    for (Actor *actor : creations) {
        actor->init();
        actors.push_back(actor);
    }
    creations.clear();

    for (Actor *actor : deletions) {
        actors.erase(std::find(actors.begin(), actors.end(), actor));
        delete actor;
    }
    deletions.clear();

    for (Actor *actor : actors) {
        actor->update();
    }
}

void ActorList::draw(Painter *painter) {
    for (Actor *actor : actors) {
        actor->draw(painter);
    }
}

void ActorList::draw_foreground(Painter *painter) {
    for (Actor *actor : actors) {
        actor->draw_foreground(painter);
    }
}
