#pragma comment(lib, "user32.lib")
#include <Windows.h>
#include <vector>
#include <string>
#include <thread>

//#include "../Source/Security/xorstr.h"

namespace Security {
	namespace Check {
		void CheckRoblox();
		BOOL AntiDebug(HWND hwnd, LPARAM lParam);
	}
}