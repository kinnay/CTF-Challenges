
#pragma once

#include "actors/actorlist.h"
#include "actors/dialog.h"
#include "assets/actorinfo.h"
#include "assets/archive.h"
#include "assets/sound.h"
#include "system/audioplayer.h"
#include "system/inputmgr.h"
#include "system/system.h"
#include "system/window.h"
#include "camera.h"


class App {
public:
    App();
    ~App();
    
    void create_actor(ActorInfo *info);
    void show_message(const std::string &message);
    void flag_collected(int id, const std::string &key);
    void trophy_collected();
    void die();
    
    void update();

    System *system;
    Window *window;
    InputMgr *inputmgr;
    AudioPlayer *audioplayer;

    ActorList *actorlist;
    GameState *gamestate;
    Archive *archive;
    CollisionMgr *collisionmgr;
    Camera *camera;
    Level *level;

private:
    void reset();

    Actor *construct_actor(ActorInfo *info);
    void prepare_dialog();

    uint64_t nexttick;
    bool dead;
    bool solved;

    Dialog *dialog;
    
    Sound *music;
    Sound *win_sound;

    uint8_t key[256];
};
