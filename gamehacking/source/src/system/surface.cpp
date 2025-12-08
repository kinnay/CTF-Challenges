
#include "system/surface.h"

#include <stdexcept>

#include <SDL2/SDL.h>

Surface::Surface(void *data, int width, int height) {
    surface = SDL_CreateRGBSurfaceWithFormatFrom(data, width, height, 32, width * 4, SDL_PIXELFORMAT_RGBA32);
    if (!surface) {
        throw std::runtime_error("SDL_CreateRGBSurfaceWithFormatFrom failed");
    }
    
    this->width = width;
    this->height = height;

    init_flipped();
}

Surface::~Surface() {
    SDL_FreeSurface(surface);
    if (flipped) {
        SDL_FreeSurface(surface);
    }
}

void Surface::init_flipped() {
    flipped = SDL_CreateRGBSurfaceWithFormat(0, width, height, 32, SDL_PIXELFORMAT_RGBA32);

    uint32_t *src = (uint32_t *)surface->pixels;
    uint32_t *dst = (uint32_t *)flipped->pixels;
    for (int y = 0; y < height; y++) {
        for (int x = 0; x < width; x++) {
            dst[y * width + x] = src[(y + 1) * width - x - 1];
        }
    }
}
