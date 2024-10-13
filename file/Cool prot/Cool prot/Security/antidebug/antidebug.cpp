#pragma comment(lib, "user32.lib")

#include "../Security.h"


void TimedMessageBox(const char* text, const char* caption, UINT type, int timeout) {
    std::thread([=]() {
        MessageBoxA(NULL, text, caption, type);
        Sleep(timeout);
        PostMessage(HWND_BROADCAST, WM_CLOSE, 0, 0);
        }).detach();
}

BOOL CALLBACK Security::Check::AntiDebug(HWND hwnd, LPARAM lParam) {
    int length = GetWindowTextLengthA(hwnd);
    if (length == 0) {
        return TRUE;
    }

    std::vector<char> title(length + 1);
    GetWindowTextA(hwnd, title.data(), length + 1);

    std::string titleStr(title.begin(), title.end());

    std::vector<std::string> blacklistedTitles = {
        "PID:", "Thread:", "Module:", "Main Thread",
        "[Elevated]", 
        "IDA", "IDA Pro", "IDA Freeware",
        "x64dbg", "x64dbg-unsigned", 
        "Process Hacker", "Resource Monitor", 
        "Cheat Engine", "OllyDbg", "Hiew",
        "WinDbg", "Immunity Debugger",
        "Sublime Text", "Notepad++",
        "Ghidra", "Radare2", 
        "Scylla", "PEiD", "LordPE", "Proxifier",
        "ExtremeDumper", "ReClass.NET",
        "TitanHide",
        "Sysinternals", "Process Explorer",
        "Fiddler", "Wireshark", 
        "Charles", "Burp Suite", 
        "Frida", "APKTool", 
        "HxD", "010 Editor", 
        "SoftICE", "Turbo Debugger", 
        "JEB", "JD-GUI", "Bytecode Viewer", 
        "DotPeek", "ILSpy", "dnSpy", 
        "PowerGREP", "ProcMon", 
        "Fakenet-NG", "INetSim", 
        "CFF Explorer", "Die (Detect It Easy)", 
        "Unpackers", "UPX", 
        "ProDG", "PCSX2 Debugger", "No$GBA", 
        "Medusa Pro", "FlashMagic", "FlashDump", 
        "API Monitor", "WinAPIOverride", 
        "TcpView", "NetMon", "Nmap",
        "BinDiff", "Diaphora", 
        "OllyDump", "PCHunter", "Syser",
        "ProcDump", "VMMap", "MemDumper", 
        "PE Explorer", "Resource Hacker",
        "WireShark", "Aircrack-ng",
        "Malzilla", "Reverse Engineering Toolkit", 
        "HTTP Analyzer", "Charles Proxy",
        "SniffPass", "Cain & Abel",
        "Wireshark", "Ettercap", "Snort", 
        "Vmware", "VirtualBox",
        "Sandboxie", "Cuckoo Sandbox", 
        "Anubis", "Detekt", 
        "OpenRCE", "BinNavi", "BOOMERANG", 
        "Relyze", "Snowman Decompiler", 
        "Metasploit", "BeEF", "Responder", 
        "AirSnare", "Kismet", 
        "Hex Workshop", "ImHex", 
        "Deviare", "Paros Proxy", 
        "IDA Python",  "Diablo2oo2's Universal Patcher" 
    };

    for (const auto& forbiddenTitle : blacklistedTitles) {
        if (titleStr.find(forbiddenTitle.c_str()) != std::string::npos) {
            TimedMessageBox(("Oh No I Got Caught Trying To Crack Am NOT russian pro cracker :sob:!!!"), ("athenis - Security"), MB_ICONERROR, 1500);
            Sleep(1500);
            exit(1);
        }
    }

    return TRUE;
}
