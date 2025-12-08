
#include "system/window.h"

#include <stdexcept>


Window::Window(int width, int height, const char *title) {
	window = SDL_CreateWindow(
        title, SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
        width, height, 0
    );
    if (!window) {
        throw std::runtime_error("SDL_CreateWindowAndRenderer failed");
    }

    surface = SDL_GetWindowSurface(window);
    if (!surface) {
        throw std::runtime_error("SDL_GetWindowSurface failed");
    }

    painter = new Painter(surface);
}

Window::~Window() {
    delete painter;
    SDL_DestroyWindow(window);
}

void Window::clear(int r, int g, int b) {
    uint32_t color = SDL_MapRGB(surface->format, r, g, b);
    SDL_FillRect(surface, NULL, color);
}

void Window::swap() {
    SDL_UpdateWindowSurface(window);
}
