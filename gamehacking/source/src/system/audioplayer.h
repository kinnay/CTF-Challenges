
#pragma once

#include "system/audiochunk.h"

#include <SDL2/SDL_mixer.h>


class AudioPlayer {
public:
	AudioPlayer();
	~AudioPlayer();
	
	void play(AudioChunk *chunk, int channel, bool loop = false);
	void stop();
};
