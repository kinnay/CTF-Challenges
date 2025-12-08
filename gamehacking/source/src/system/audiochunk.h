
#pragma once

#include <SDL2/SDL_mixer.h>

class AudioChunk {
public:
	AudioChunk(const void *data, size_t size);
	~AudioChunk();

	Mix_Chunk *chunk;
};
