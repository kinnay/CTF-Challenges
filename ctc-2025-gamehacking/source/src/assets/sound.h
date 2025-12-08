
#pragma once

#include "assets/stream.h"
#include "system/audiochunk.h"
#include "system/audioplayer.h"

class Archive;

class Sound {
public:
	Sound(Stream *stream, Archive *archive);
    ~Sound();

	void play(AudioPlayer *player, int channel, bool loop = false);

private:
	AudioChunk *chunk;
};
