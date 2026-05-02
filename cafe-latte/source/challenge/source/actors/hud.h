
#pragma once

#include "actors/actor.h"
#include "system/texture.h"

class HUD : public Actor {
public:
    HUD(App *app);

    void draw();

private:
    Texture *digits[16];
};
