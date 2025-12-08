
#pragma once

#include "assets/stream.h"

#include <string>

enum class ActorType {
    Invalid,
    HUD,
    Player,
    Background,
    Solid,
    Text,
    Item,
    Effect,
    Flag,
    Trophy,
    Block,
    Dialog,
    Spikes,
    SolidOnTop
};

class ActorInfo {
public:
    ActorInfo();
    ActorInfo(Stream *stream);

    ActorType type;
    int x, y;
    int nx, ny;
    int dx, dy;
    int w, h;
    std::string texture;
    std::string text;
    int param;
    bool global;
};
