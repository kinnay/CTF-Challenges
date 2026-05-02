
#pragma once

#include "actors/actor.h"
#include "system/texture.h"

#include <string>
#include <map>


class Message : public Actor {
public:
    Message(App *app, const std::string &message);

    void draw();

private:
    std::string message;
    std::map<char, Texture *> font;
};
