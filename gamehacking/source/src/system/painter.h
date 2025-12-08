
#pragma once

#include "system/surface.h"

#include <SDL2/SDL.h>

class Painter {
public:
    Painter(SDL_Surface *surface);

    void draw(Surface *surface, int x, int y, bool flipped = false);
    void draw(Surface *surface, int x, int y, int sx, int sy, int w, int h, bool flipped = false);

private:
    SDL_Surface *surface;
};
