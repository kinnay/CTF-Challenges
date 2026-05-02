
#pragma once

#include "actors/actor.h"
#include "system/texture.h"

class Background : public Actor {
public:
    Background(App *app);

    void draw();

private:
    Texture *texture_top;
    Texture *texture_middle;
    Texture *texture_bottom;
};
