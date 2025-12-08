
#pragma once

#include "system/enum.h"

class InputMgr {
public:
	InputMgr();
	
	void update();
	
	bool pressed[Key_Last];
	bool hold[Key_Last];
	bool released[Key_Last];
};
