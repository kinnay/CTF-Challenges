
#pragma once

#include "assets/actorinfo.h"
#include "assets/level.h"
#include "math/vector.h"
#include "physics/collider.h"
#include "physics/collisionmgr.h"
#include "system/inputmgr.h"
#include "system/painter.h"
#include "system/audioplayer.h"
#include "camera.h"
#include "gamestate.h"

#include <vector>


class App;
class ActorList;
class Archive;


class Actor {
public:
    Actor(App *app, ActorInfo *info);
    ~Actor();

    void init();
    void destroy();
    
    virtual void update();
    
    virtual void draw(Painter *painter);
    virtual void draw_foreground(Painter *painter);

    virtual Collider *create_collider();
    virtual void handle_collision(Actor *other, Collider::Side side);

    Vector position;
    Vector speed;

    ActorType type;

    Collider *collider;
    ActorInfo *info;

protected:
    App *app;
    ActorList *actorlist;
    Archive *archive;
    CollisionMgr *collisionmgr;
    InputMgr *inputmgr;
    AudioPlayer *audioplayer;
    Camera *camera;
    Level *level;
    GameState *gamestate;
};
