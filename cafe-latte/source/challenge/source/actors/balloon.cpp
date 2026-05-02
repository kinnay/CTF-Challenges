
#include "actors/balloon.h"
#include "system/drawer.h"

#include "constants.h"
#include "random.h"

#include <cmath>


Balloon::Balloon(App *app, int value) : Actor(app) {
    color = value;

    for (int i = 0; i < 7; i++) {
        std::string name = std::string("balloons/") + colors[color & 7] + "/" + std::to_string(i);
        textures[i] = loader->texture(name);
    }

    digit = loader->texture("digits/" + std::to_string(color));

    angle = random_double(-M_PI / 8, M_PI / 8);

    position.x = random_double(0, 1280 - 128);
    position.y = -256;
    position.z = random_double(1, 10);

    float velocity = random_double(2, 4);

    speed.x = -sinf(angle) * velocity;
    speed.y = cosf(angle) * velocity;

    index = 0;
}

void Balloon::update() {
    Actor::update();

    if (index == 0) {
        if (position.y > 800) {
            destroy();
        }
    }
    else {
        if (index == 6) {
            destroy();
        }
        else {
            index++;
        }
    }
}

void Balloon::draw() {
    Actor::draw();
    textures[index]->draw(position.x, position.y, position.z, angle);
    if (index == 0) {
        digit->draw(position.x + 32, position.y + 36, position.z, angle);
    }
}

void Balloon::touch() {
    if (!popped()) {
        gamestate->type(color);
        pop();
    }
}

void Balloon::pop() {
    if (!popped()) {
        index++;
    }
}

bool Balloon::popped() {
    return index > 0;
}

bool Balloon::touched() {
    if (!inputmgr->pressed[Key_Touch]) {
        return false;
    }
    
    float dx = inputmgr->x - position.x - 64;
    float dy = 720 - inputmgr->y - position.y - 64 + 7;
    float dist = sqrtf(dx * dx + dy * dy);

    float angle = atan2f(dy, dx) - this->angle;
    float nx = cosf(angle) * dist;
    float ny = sinf(angle) * dist;
    
    // Balloon is approximately 72 x 104 pixels big.
    return nx * nx / (36 * 36) + ny * ny / (52 * 52) <= 1;
}
