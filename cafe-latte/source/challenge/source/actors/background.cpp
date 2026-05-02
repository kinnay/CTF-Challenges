
#include "actors/background.h"

Background::Background(App *app) : Actor(app) {
    texture_top = loader->texture("backgrounds/top");
    texture_middle = loader->texture("backgrounds/middle");
    texture_bottom = loader->texture("backgrounds/bottom");
}

void Background::draw() {
    Actor::draw();
    for (int x = 0; x < 5; x++) {
        texture_top->draw(x * 256, 464, 0);
        texture_middle->draw(x * 256, 208, 0);
        texture_bottom->draw(x * 256, -48, 0);
    }
}
