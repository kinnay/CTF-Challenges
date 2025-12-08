
#pragma once

#include "actors/actor.h"
#include "system/painter.h"

#include <vector>

class ActorList {
public:
    ~ActorList();

    void reset();

    void update();

    void draw(Painter *painter);
    void draw_foreground(Painter *painter);

    void add(Actor *actor);
    void destroy(Actor *actor);

    std::vector<Actor *> actors;

private:
    std::vector<Actor *> creations;
    std::vector<Actor *> deletions;
};
