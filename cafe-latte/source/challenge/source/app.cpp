
#include "app.h"

#include "actors/background.h"
#include "actors/balloon.h"
#include "actors/hud.h"
#include "actors/message.h"

#include "data.h"

#include <coreinit/cache.h>
#include <coreinit/debug.h>
#include <coreinit/memdefaultheap.h>
#include <coreinit/time.h>

#include <gfd.h>

#include <gx2/enum.h>
#include <gx2/event.h>
#include <gx2/mem.h>
#include <gx2/texture.h>
#include <gx2/utils.h>

#include <whb/gfx.h>

#include <cstdlib>

#include <stdexcept>


#define GX2_DISPATCH_PARAMS_ALIGNMENT 0x100
#define GX2_EXPORT_BUFFER_ALIGNMENT 0x100

// Important: this must be a multiple of 256 bytes
#define EXPORT_BUFFER_SIZE 0x100


extern "C" void GX2SetShaderExportBuffer(void *buffer, uint32_t size);


GX2SamplerVar *GX2GetComputeSamplerVar(const GX2ComputeShader *shader, const char *name)
{
    for (unsigned int i = 0; i < shader->samplerVarCount; i++)
    {
       if (strcmp(shader->samplerVars[i].name, name) == 0)
           return &(shader->samplerVars[i]);
    }
    return NULL;
}


App::App() {
    // Initialize the game
    inputmgr = new InputMgr();
    actorlist = new ActorList();
    gamestate = new GameState();
    loader = new AssetLoader();

    // Next, we load the compute shader that validates the player input from
    // the data segment.
    shader = WHBGfxLoadGFDComputeShader(0, compute_shader);

    // Now find and allocate the uniform block. This is used to provide a
    // hardcoded encryption key and the player input to the shader.
    uniform_block = GX2GetComputeUniformBlock(shader, "params");
    uniform_buffer = (UniformStruct *)MEMAllocFromDefaultHeapEx(
        uniform_block->size, GX2_UNIFORM_BLOCK_ALIGNMENT
    );

    // The dispatch params specify how many work groups are used by the shader.
    dispatch_params = (GX2DispatchParams *)MEMAllocFromDefaultHeapEx(
        sizeof(GX2DispatchParams), GX2_DISPATCH_PARAMS_ALIGNMENT
    );

    // The export buffer allows the shader to provide data back to the CPU.
    // We also use this buffer to pass the encrypted flag verification matrix
    // and other buffers to the GPU.
    export_buffer = MEMAllocFromDefaultHeapEx(
        EXPORT_BUFFER_SIZE, GX2_EXPORT_BUFFER_ALIGNMENT
    );
    memset(export_buffer, 0, EXPORT_BUFFER_SIZE);

    // Finally, reset the game state
    reset();
}

App::~App() {
    delete actorlist;
    delete gamestate;
    delete loader;
    delete inputmgr;

    // We should clean up the shader stuff here too, but it doesn't really
    // matter as the OS will clean it up anyway when the program exits.
}

void App::reset() {
    actorlist->reset();
    gamestate->reset();

    srand(OSGetSystemTick());

    actorlist->add(new Background(this));
    actorlist->add(new HUD(this));
    spawn(0);

    timer = 0;
    counter = 0;
    message = nullptr;
}

void App::update() {
    inputmgr->update();

    if (!message) {
        if (inputmgr->pressed[Key_B]) {
            gamestate->backspace();
        }

        check_balloon_touches();

        if (gamestate->count == INPUT_LENGTH) {
            check_input();
        }
        else {
            timer++;
            if (timer == 10) {
                counter++;
                if (counter == 16) {
                    counter = 0;
                }
                spawn(counter);
                timer = 0;
            }
        }
    }
    else {
        if (inputmgr->pressed[Key_A]) {
            reset();
        }
    }

    actorlist->update();
}

void App::draw() {
    actorlist->draw();
}

void App::spawn(int color) {
    actorlist->add(new Balloon(this, color));
}

void App::check_balloon_touches() {
    Balloon *best = nullptr;
    for (Actor *actor : actorlist->actors) {
        Balloon *balloon = dynamic_cast<Balloon *>(actor);
        if (balloon && balloon->touched()) {
            if (!best || best->position.z < balloon->position.z) {
                best = balloon;
            }
        }
    }

    if (best) {
        best->touch();
    }
}

void App::check_input() {
    for (Actor *actor : actorlist->actors) {
        Balloon *balloon = dynamic_cast<Balloon *>(actor);
        if (balloon) {
            balloon->pop();
        }
    }

    std::string text = run_shader();

    message = new Message(this, text);
    message->position.x = 640 - 14 * text.size();
    message->position.y = 400;

    actorlist->add(message);
}

std::string App::run_shader() {
    // This function runs the flag verification shader on the GPU and returns
    // the result.

    // We first initialize the uniform buffer. This allows us to pass data from
    // the CPU to the shader. We provide a hardcoded key to decrypt the flag
    // verification matrix.
    uniform_buffer->key[0] = 0x7DDD591D;
    uniform_buffer->key[1] = 0xDCF97E8F;
    uniform_buffer->key[2] = 0xA78CECCD;
    uniform_buffer->key[3] = 0x561FD75A;

    // Now, we encode the player input into a byte array
    for (int i = 0; i < 4; i++) {
        uint32_t value = 0;
        for (int j = 0; j < 8; j++) {
            value = (value << 4) | gamestate->values[i * 8 + j];
        }
        uniform_buffer->inp[i] = value;
    }

    memcpy(uniform_buffer->constants, binary_blob, 0xC60);

    // It is important to flush the CPU cache and invalidate the GPU cache, as
    // this does not happen automatically.
    DCFlushRange(uniform_buffer, uniform_block->size);
    GX2Invalidate(GX2_INVALIDATE_MODE_CPU, uniform_buffer, uniform_block->size);

    // One work group is enough for us
    dispatch_params->numGroupsX = 1;
    dispatch_params->numGroupsY = 1;
    dispatch_params->numGroupsZ = 1;
    dispatch_params->_padding = 0;

    // Make sure that the GPU can see the latest dispatch params.
    DCFlushRange(dispatch_params, sizeof(GX2DispatchParams));
    GX2Invalidate(
        GX2_INVALIDATE_MODE_CPU, dispatch_params, sizeof(GX2DispatchParams)
    );

    // Now, we start initializing the GPU state. First enable compute shader
    // mode and specify the flag verification shader.
    GX2SetShaderMode(GX2_SHADER_MODE_COMPUTE_SHADER);
    GX2SetComputeShader(shader);

    // Configure the uniform block for the shader
    GX2SetComputeUniformBlock(
        uniform_block->offset, uniform_block->size, uniform_buffer
    );

    // Configure the export buffer
    GX2SetShaderExportBuffer(export_buffer, EXPORT_BUFFER_SIZE);

    // Execute the shader
    GX2DispatchCompute(dispatch_params);

    // Wait until the shader is complete
    GX2DrawDone();

    // Make sure that the CPU receives the latest copy of the export buffer.
    GX2Invalidate(
        GX2_INVALIDATE_MODE_EXPORT_BUFFER, export_buffer, EXPORT_BUFFER_SIZE
    );
    DCInvalidateRange(export_buffer, EXPORT_BUFFER_SIZE);

    // Go back to uniform register mode (for regular drawing)
    GX2SetShaderMode(GX2_SHADER_MODE_UNIFORM_REGISTER);

    return std::string((const char *)export_buffer);
}

