
#include "assets/actorinfo.h"

ActorInfo::ActorInfo() {
    type = ActorType::Invalid;
    x = y = 0;
    nx = ny = 1;
    dx = dy = 16;
    w = h = 1;
    param = 0;
    global = false;
}

ActorInfo::ActorInfo(Stream *stream) {
    type = (ActorType)stream->u8();
    x = stream->s16();
    y = stream->s16();
    nx = stream->u8();
    ny = stream->u8();
    dx = stream->u16();
    dy = stream->u16();
    w = stream->u8();
    h = stream->u8();
    texture = stream->string();
    text = stream->string();
    param = stream->u8();

    global = false;
}
