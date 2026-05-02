#include "maintask.h"

#include <rio.h>

int main()
{
    // Initialize RIO with main task
    if (!rio::Initialize<MainTask>())
        return -1;

    // Main loop
    rio::EnterMainLoop();

    // Exit RIO
    rio::Exit();

    return 0;
}
