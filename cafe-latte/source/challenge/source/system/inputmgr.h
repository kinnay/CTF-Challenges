
#pragma once

#include "system/enum.h"

#include <controller/rio_ControllerMgr.h>

class InputMgr {
public:
	InputMgr();
	
	void update();
	
	bool pressed[Key_Last];
	bool hold[Key_Last];
	bool released[Key_Last];

	float x, y;

private:
	void update_key(rio::Controller *controller, uint32_t mask, Key key);
};
