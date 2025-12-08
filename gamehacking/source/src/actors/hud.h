
#pragma once

#include "actors/actor.h"
#include "assets/font.h"
#include "assets/sprite.h"

class HUD : public Actor {
public:
    HUD(App *app, ActorInfo *info);

    void draw(Painter *painter);

private:
    Font *font;
};
