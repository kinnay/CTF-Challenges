
#include "system/audioplayer.h"

#include <SDL2/SDL_mixer.h>

#include <stdexcept>


AudioPlayer::AudioPlayer() {
	int result = Mix_OpenAudio(48000, AUDIO_S16LSB, 2, 2048);
	if (result != 0) {
		throw std::runtime_error("MIX_OpenAudio failed");
	}
}

AudioPlayer::~AudioPlayer() {
	Mix_CloseAudio();
}

void AudioPlayer::play(AudioChunk *chunk, int channel, bool loop) {
	Mix_PlayChannel(channel, chunk->chunk, loop ? -1 : 0);
}

void AudioPlayer::stop() {
	Mix_HaltChannel(-1);
}
