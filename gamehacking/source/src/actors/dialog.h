
#pragma once

#include "actors/actor.h"
#include "assets/font.h"
#include "assets/spritesheet.h"

#include <string>
#include <vector>


class Dialog : public Actor {
public:
    Dialog(App *app, ActorInfo *info);

    void update();
    void draw(Painter *painter);

    void show(const std::string &message);
    bool active();

private:
    Font *font;
    SpriteSheet *sheet;

    std::string message;
    int width, height;
};
