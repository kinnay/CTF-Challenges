
#pragma once

#include "actors/actor.h"
#include "assets/font.h"

class Text : public Actor {
public:
    Text(App *app, ActorInfo *info);

    void draw(Painter *painter);

private:
    Font *font;
};
