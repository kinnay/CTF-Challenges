
#pragma once

#include "system/painter.h"

#include <SDL2/SDL.h>

class Window {
public:
    Window(int width, int height, const char *title);
    ~Window();

    void clear(int r, int g, int b);
    void swap();

    Painter *painter;

private:
    SDL_Window *window;
    SDL_Surface *surface;
};
