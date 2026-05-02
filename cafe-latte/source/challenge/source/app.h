
#pragma once

#include "actors/actorlist.h"
#include "actors/message.h"

#include "system/inputmgr.h"

#include "assetloader.h"

#include <gx2/draw.h>
#include <gx2/shaders.h>

#include <string>


struct UniformStruct {
    uint32_t key[4];
    uint32_t inp[4];

    uint8_t constants[0xC60];
};


class App {
public:
    App();
    ~App();
    
    void update();
    void draw();

    InputMgr *inputmgr;
    ActorList *actorlist;
    GameState *gamestate;
    AssetLoader *loader;

private:
    void reset();
    void spawn(int color);
    void check_balloon_touches();
    void check_input();
    std::string run_shader();

    int timer;
    int counter;

    Message *message;

    GX2ComputeShader *shader;
    GX2DispatchParams *dispatch_params;
    GX2UniformBlock *uniform_block;
    UniformStruct *uniform_buffer;
    void *export_buffer;
};
