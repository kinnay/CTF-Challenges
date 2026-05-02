
#include "gamestate.h"

#include <cstring>

GameState::GameState() {
    reset();
}

void GameState::reset() {
    count = 0;
}

void GameState::type(int value) {
    if (count < INPUT_LENGTH) {
        values[count] = value;
        count++;
    }
}

void GameState::backspace() {
    if (count > 0) {
        count--;
    }
}
