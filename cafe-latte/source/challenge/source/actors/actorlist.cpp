
#include "actors/actorlist.h"

#include <algorithm>

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

void ActorList::draw() {
    // Sorting is necessary to make transparency work correctly
    std::vector<Actor *> sorted = actors;
    std::sort(sorted.begin(), sorted.end(), [](Actor *a, Actor *b) {
        return a->position.z < b->position.z;
    });

    for (Actor *actor : sorted) {
        actor->draw();
    }
}
