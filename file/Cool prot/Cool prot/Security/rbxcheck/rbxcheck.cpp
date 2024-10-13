#include "../Security.h"

void Security::Check::CheckRoblox() {
    // roblox checker
    if (!FindWindowA(0, "Roblox")) {
        MessageBox(NULL, ("Roblox Not Found"), ("athenis"), MB_OK | MB_ICONERROR);
        Sleep(1500);
        exit(0);
    }
}
