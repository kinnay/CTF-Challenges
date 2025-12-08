
#include "actors/hud.h"
#include "assets/archive.h"

#include <format>

HUD::HUD(App *app, ActorInfo *info) : Actor(app, info) {
    font = archive->font("white");
}

void HUD::draw(Painter *painter) {
    font->draw(painter, 350, 30, std::format("SCORE: {}", gamestate->score));
    font->draw(painter, 250, 30, std::format("FLAGS: {}", gamestate->flags));
}
