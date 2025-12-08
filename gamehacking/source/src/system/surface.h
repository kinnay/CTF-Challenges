
#pragma once

#include <SDL2/SDL.h>

class Surface {
public:
    Surface(void *data, int width, int height);
    ~Surface();

    SDL_Surface *surface;
    SDL_Surface *flipped;

    int width, height;

private:
    void init_flipped();
};
