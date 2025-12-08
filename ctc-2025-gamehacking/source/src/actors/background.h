
#pragma once

#include "actors/actor.h"
#include "assets/texture.h"

class Background : public Actor {
public:
    Background(App *app, ActorInfo *info);

    void draw(Painter *painter);

private:
    Texture *texture;
};
