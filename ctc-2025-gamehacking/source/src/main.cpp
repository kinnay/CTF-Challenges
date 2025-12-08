
#include "app.h"

#include <emscripten.h>

App *app;

void tick() {
    app->update();
}

int main() {
    app = new App();
    emscripten_set_main_loop(tick, 0, false);
    return 0;
}
