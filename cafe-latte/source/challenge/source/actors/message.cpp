
#include "actors/message.h"


Message::Message(App *app, const std::string &message) : Actor(app) {
    this->message = message;

    for (int i = 32; i <= 126; i++) {
        font[i] = loader->texture(std::string("font/") + std::to_string(i));
    }
}

void Message::draw() {
    Actor::draw();

    int x = 0;
    for (char c : message) {
        if (font.contains(c)) {
            font[c]->draw(position.x + x, position.y, 20, 0, .75);
        }
        x += 28;
    }
}
