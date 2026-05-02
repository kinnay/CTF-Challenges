
#pragma once

#include <cstdint>

#include "constants.h"


class GameState {
public:
    GameState();

    void reset();
    void type(int value);
    void backspace();

    int values[INPUT_LENGTH];
    uint8_t count;
};
