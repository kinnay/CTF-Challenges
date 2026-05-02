
#pragma once

#include "actors/actor.h"

#include <vector>

class ActorList {
public:
    ~ActorList();

    void reset();

    void update();

    void draw();

    void add(Actor *actor);
    void destroy(Actor *actor);

    std::vector<Actor *> actors;

private:
    std::vector<Actor *> creations;
    std::vector<Actor *> deletions;
};
