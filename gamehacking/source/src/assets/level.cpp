
#include "assets/level.h"
#include "assets/archive.h"

Level::Level(Stream *stream, Archive *archive) {
    min_x = stream->s16();
    max_x = stream->s16();

    size_t count = stream->u8();
    for (size_t i = 0; i < count; i++) {
        ActorInfo *info = new ActorInfo(stream);
        info->global = true;
        
        actors.push_back(info);
    }
}

Level::~Level() {
    for (ActorInfo *info : actors) {
        delete info;
    }
}
