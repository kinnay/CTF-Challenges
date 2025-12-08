
#include "gamestate.h"

GameState::GameState() {
    reset();
}

void GameState::reset() {
    score = 0;
    flags = 0;
}
