
#pragma once

#include "assets/actorinfo.h"
#include "assets/stream.h"

class Archive;

#include <vector>

class Level {
public:
    Level(Stream *stream, Archive *archive);
    ~Level();

    int min_x;
    int max_x;
    
    std::vector<ActorInfo *> actors;
};
