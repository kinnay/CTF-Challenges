
#include "system/painter.h"

Painter::Painter(SDL_Surface *surface) {
    this->surface = surface;
}

void Painter::draw(Surface *surf, int x, int y, bool flipped) {
    SDL_Rect dst = {x, y};
    SDL_BlitSurface(flipped ? surf->flipped : surf->surface, NULL, surface, &dst);
}

void Painter::draw(Surface *surf, int x, int y, int sx, int sy, int w, int h, bool flipped) {
    if (!flipped) {
        SDL_Rect src = {sx, sy, w, h};
        SDL_Rect dst = {x, y};
        SDL_BlitSurface(surf->surface, &src, surface, &dst);
    }
    else {
        SDL_Rect src = {surf->width - sx - w, surf->height - sy - h, w, h};
        SDL_Rect dst = {x, y};
        SDL_BlitSurface(surf->flipped, &src, surface, &dst);
    }
}
