
#include "system/audiochunk.h"

#include <SDL2/SDL_mixer.h>

#include <stdexcept>


AudioChunk::AudioChunk(const void *data, size_t size) {
	SDL_RWops *rwops = SDL_RWFromConstMem(data, size);

	chunk = Mix_LoadWAV_RW(rwops, 1);
	if (!chunk) {
		const char *error = SDL_GetError();
		throw std::runtime_error(error);
		throw std::runtime_error("Mix_LoadWAV_RW failed");
	}
}

AudioChunk::~AudioChunk() {
	Mix_FreeChunk(chunk);
}
