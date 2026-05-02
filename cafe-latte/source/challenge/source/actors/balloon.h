
#pragma once

#include "actors/actor.h"
#include "system/texture.h"
#include "vector.h"


class Balloon : public Actor {
public:
    Balloon(App *app, int value);

    void update();
    void draw();

    void touch();
    void pop();
    bool popped();
    bool touched();

private:
    Texture *textures[7];
    Texture *digit;

    float angle;
    int index;
    int color;
};
