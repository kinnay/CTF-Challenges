
#include "actors/dialog.h"
#include "assets/archive.h"

Dialog::Dialog(App *app, ActorInfo *info) : Actor(app, info) {
    font = archive->font("white");
    sheet = archive->spritesheet("dialog");
}

void Dialog::show(const std::string &message) {
    this->message = message;

    width = 0;
    height = 0;

    int length = 0;
    for (char c : message) {
        if (c == '\n') {
            if (length > width) {
                width = length;
            }
            length = 0;
            height++;
        }
        else {
            length++;
        }
    }

    if (length > width) {
        width = length;
    }
    height++;
}

bool Dialog::active() {
    return !message.empty();
}

void Dialog::update() {
    if (
        inputmgr->pressed[Key_z] || inputmgr->pressed[Key_x] ||
        inputmgr->pressed[Key_Left] || inputmgr->pressed[Key_Right] ||
        inputmgr->pressed[Key_Up]
    ) {
        message = "";
    }
}

void Dialog::draw(Painter *painter) {
    if (!active()) return;

    int w = 32 + (width + 1) / 2 * 16;
    int h = 32 + height * 16;
    int x = 240 - w / 2;
    int y = 180 - h / 2;

    sheet->draw(painter, x, y, 0);
    sheet->draw(painter, x + w - 16, y, 2);
    sheet->draw(painter, x, y + h - 16, 6);
    sheet->draw(painter, x + w - 16, y + h - 16, 8);

    for (int i = 0; i < (width + 1) / 2; i++) {
        for (int j = 0; j < height; j++) {
            sheet->draw(painter, x + 16 + 16 * i, y + 16 + 16 * j, 4);
        }
        sheet->draw(painter, x + 16 + 16 * i, y, 1);
        sheet->draw(painter, x + 16 + 16 * i, y + h - 16, 7);
    }

    for (int i = 0; i < height; i++) {
        sheet->draw(painter, x, y + 16 + 16 * i, 3);
        sheet->draw(painter, x + w - 16, y + 16 + 16 * i, 5);
    }

    y += 16;

    std::string line;
    for (char c : message) {
        if (c == '\n') {
            x = 240 - line.length() * 4;
            font->draw(painter, x, y, line);
            y += 16;
            line = "";
        }
        else {
            line += c;
        }
    }

    x = 240 - line.length() * 4;
    font->draw(painter, x, y, line);
}
