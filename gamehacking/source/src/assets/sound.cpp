
#include "assets/sound.h"

Sound::Sound(Stream *stream, Archive *archive) {
	size_t size = stream->u32();
	uint8_t *data = stream->read(size);

	chunk = new AudioChunk(data, size);
}

Sound::~Sound() {
    delete chunk;
}

void Sound::play(AudioPlayer *player, int channel, bool loop) {
	player->play(chunk, channel, loop);
}
