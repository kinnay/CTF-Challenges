
#include "app.h"

#include "actors/background.h"
#include "actors/block.h"
#include "actors/effect.h"
#include "actors/flag.h"
#include "actors/hud.h"
#include "actors/item.h"
#include "actors/player.h"
#include "actors/solid.h"
#include "actors/solidontop.h"
#include "actors/spikes.h"
#include "actors/text.h"
#include "actors/trophy.h"

#include "rc4.h"
#include "sha1.h"

uint8_t encrypted_flag[] = {
    160, 127, 98, 50, 46, 201, 234, 59, 160, 98, 166, 25, 158, 102, 31, 170, 204, 174, 234, 244, 35, 72, 7, 40, 176, 85, 14, 159, 230, 82, 6, 136, 190, 57, 222, 156, 168, 123, 61, 94, 160, 112, 196, 78, 126, 29, 194, 64, 88, 142, 178, 175, 91, 176, 9, 22, 113, 135, 88, 94, 106, 130, 195, 103, 230, 12
};

App::App() {
    camera = new Camera();

    system = new System();
    window = new Window(480, 360, "Game Hacking Challenge");
    inputmgr = new InputMgr();
    audioplayer = new AudioPlayer();

    archive = new Archive("assets.arc");
    actorlist = new ActorList();
    collisionmgr = new CollisionMgr();
    gamestate = new GameState();

    level = archive->level("1-1");

    music = archive->sound("music");
    music->play(audioplayer, 0, true);

    win_sound = archive->sound("win");

    nexttick = 0;
    
    reset();
}

App::~App() {
    delete actorlist;
    delete gamestate;
    delete collisionmgr;
    delete archive;
    delete inputmgr;
    delete window;
    delete system;
    delete camera;
}

void App::reset() {
    actorlist->reset();
    gamestate->reset();
    
    dead = false;
    solved = false;

    for (ActorInfo *info : level->actors) {
        create_actor(info);
    }

    prepare_dialog();

    memset(key, 0, sizeof(key));
}

void App::create_actor(ActorInfo *info) {
    for (int i = 0; i < info->nx; i++) {
        for (int j = 0; j < info->ny; j++) {
            Actor *actor = construct_actor(info);
            actor->position.x = info->x + i * info->dx;
            actor->position.y = info->y + j * info->dy;
        }
    }        
}

Actor *App::construct_actor(ActorInfo *info) {
    if (info->type == ActorType::HUD) return new HUD(this, info);
    else if (info->type == ActorType::Player) return new Player(this, info);
    else if (info->type == ActorType::Background) return new Background(this, info);
    else if (info->type == ActorType::Solid) return new Solid(this, info);
    else if (info->type == ActorType::Text) return new Text(this, info);
    else if (info->type == ActorType::Item) return new Item(this, info);
    else if (info->type == ActorType::Effect) return new Effect(this, info);
    else if (info->type == ActorType::Flag) return new Flag(this, info);
    else if (info->type == ActorType::Trophy) return new Trophy(this, info);
    else if (info->type == ActorType::Block) return new Block(this, info);
    else if (info->type == ActorType::Spikes) return new Spikes(this, info);
    else if (info->type == ActorType::SolidOnTop) return new SolidOnTop(this, info);
    else {
        throw std::runtime_error("Unimplemented actor type");
    }
}

void App::prepare_dialog() {
    ActorInfo *info = new ActorInfo();
    info->type = ActorType::Dialog;

    dialog = new Dialog(this, info);
}

void App::flag_collected(int id, const std::string &word) {
    // Just some random operations to make reverse engineering more difficult
    for (int i = 0; i < word.size(); i++) {
        key[id * 20 + i] = word[i] * (7 + i * 15 + id * 31);
    }
}

void App::trophy_collected() {
    if (gamestate->flags != 5) {
        die();
        return;
    }

    for (int i = 0; i < 256; i++) {
        printf("%i, ", key[i]);
    }
    printf("\n");

    // More obfuscation memes
    SHA1 sha1;
    sha1.h0 = 0;
    sha1.h1 = 1;
    sha1.h2 = 2;
    sha1.h3 = 3;
    sha1.h4 = 4;

    sha1.update(key + 192);
    sha1.update(key + 64);
    sha1.update(key + 128);
    sha1.update(key);

    if (sha1.h4 != 2237598466) {
        die();
    }

    uint32_t values[] = {
        sha1.h0, sha1.h1, sha1.h2, sha1.h3
    };

    uint8_t message[sizeof(encrypted_flag) + 1];
    memcpy(message, encrypted_flag, sizeof(encrypted_flag));
    message[sizeof(encrypted_flag)] = 0;

    RC4 rc4;
    rc4.setkey((uint8_t *)values, 16);
    rc4.decrypt(message, sizeof(message) - 1);

    std::string string((char *)message);
    show_message(string);
    solved = true;

    audioplayer->stop();

    win_sound->play(audioplayer, 0);
}

void App::show_message(const std::string &message) {
    dialog->show(message);
}

void App::die() {
    dead = true;
}

void App::update() {
    if (!solved) {
        uint64_t timer = SDL_GetTicks64();
        while (timer > nexttick) {
            inputmgr->update();
            if (dialog->active()) {
                dialog->update();
            }
            else {
                actorlist->update();
                collisionmgr->update();
            }
            nexttick += 1000 / 60;
        }
    }

    window->clear(97, 133, 248);
    actorlist->draw(window->painter);
    actorlist->draw_foreground(window->painter);
    window->swap();

    if (dead) {
        reset();
    }
}
