
#include "system/inputmgr.h"

#include <controller/rio_ControllerMgr.h>

#include <cstring>


InputMgr::InputMgr() {
	memset(pressed, 0, sizeof(pressed));
	memset(hold, 0, sizeof(hold));
	memset(released, 0, sizeof(released));
	x = y = 0;
}

void InputMgr::update() {
	memset(pressed, 0, sizeof(pressed));
	memset(released, 0, sizeof(released));

	rio::Controller* controller = rio::ControllerMgr::instance()->getGamepad(0);
    if (!controller || !controller->isConnected())
    {
        controller = rio::ControllerMgr::instance()->getMainGamepad();
        RIO_ASSERT(controller);
    }

	update_key(controller, rio::Controller::PAD_IDX_A, Key_A);
	update_key(controller, rio::Controller::PAD_IDX_B, Key_B);
	update_key(controller, rio::Controller::PAD_IDX_X, Key_X);
	update_key(controller, rio::Controller::PAD_IDX_Y, Key_Y);
	update_key(controller, rio::Controller::PAD_IDX_UP, Key_Up);
	update_key(controller, rio::Controller::PAD_IDX_DOWN, Key_Down);
	update_key(controller, rio::Controller::PAD_IDX_LEFT, Key_Left);
	update_key(controller, rio::Controller::PAD_IDX_RIGHT, Key_Right);

	pressed[Key_Touch] = controller->isPointerOnNow();
	hold[Key_Touch] = controller->isPointerOn();
	released[Key_Touch] = controller->isPointerOffNow();

	rio::Vector2f position = controller->getPointer();
	x = position.x;
	y = position.y;
}

void InputMgr::update_key(rio::Controller *controller, uint32_t mask, Key key) {
	pressed[key] = controller->isTrig(key);
	hold[key] = controller->isHold(key);
	released[key] = controller->isRelease(key);
}

