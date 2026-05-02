
#pragma once

#include "system/inputmgr.h"

#include "assetloader.h"
#include "gamestate.h"

#include "vector.h"


class App;
class ActorList;


class Actor {
public:
    Actor(App *app);
    virtual ~Actor();

    virtual void init();
    virtual void destroy();
    virtual void update();
    virtual void draw();

    Vector position;
    Vector speed;

    bool pending_deletion;

protected:
    App *app;
    ActorList *actorlist;
    AssetLoader *loader;
    InputMgr *inputmgr;
    GameState *gamestate;
};
