
#include "actors/hud.h"

#include "system/drawer.h"

#include "constants.h"


HUD::HUD(App *app) : Actor(app) {
    for (int i = 0; i < 16; i++) {
        digits[i] = loader->texture("digits/" + std::to_string(i));
    }

    position.z = .5;
}

void HUD::draw() {
    Actor::draw();

    for (int i = 0; i < INPUT_LENGTH; i++) {
        int x = 1280 - 43 - 20 * INPUT_LENGTH + i * 20;
        int y = 720 - 64;
        if (i < gamestate->count) {
            digits[gamestate->values[i]]->draw(x, y, .6, 0, .5);
        }
        else {
            Drawer::rectangle(
                x + 15, y + 10, 8, 8, 0, 0, 0, .6
            );
        }
    }
}
