
#include "system/system.h"

#include <stdexcept>

#include <SDL2/SDL.h>


System::System() {
	if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO) < 0) {
		throw std::runtime_error("SDL_Init failed");
	}
}

System::~System() {
	SDL_Quit();
}
