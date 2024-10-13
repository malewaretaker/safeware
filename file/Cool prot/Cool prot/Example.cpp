#include <iostream>
#include <thread>
#include <string>
#include <random>
#include <filesystem>
#include <cstdlib>
#include <urlmon.h>
#include <shlobj.h>
#include <wlanapi.h>
#include <windows.h>
#include <TlHelp32.h>
#include <bcrypt.h> // For cryptographic functions
#include "Security/json.hpp"
#include <fstream>

#include "S_auth/Sentinal.h"
#include "Security/Security.h"
#include "Security/Encrypt/skCrypter.h"
using json = nlohmann::json;
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "Wlanapi.lib")
#pragma comment(lib, "bcrypt.lib") 
// all security below is owned by koda/made by koda, if u use please credit.

// creds to https://github.com/ac3ss0r/obfusheader.h for encryption

enum WLAN_CONNECTION_STATE {
    wlan_not_connected,
    wlan_connected,
    wlan_connecting,
    wlan_disconnecting,
    wlan_connected_authenticating
};




void clearConsole() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");  // for linux and shi love yall cuh <3
#endif
}

bool IsDebuggerAttached() {
    return IsDebuggerPresent() != 0x0000000000;
}

bool IsRemoteDebuggerAttached() {
    BOOL debuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
    return debuggerPresent != 0;
}

bool IsDebuggerAttachedNt() {
    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);
    NTSTATUS status;
    DWORD ProcessDebugPort = 7;
    HINSTANCE hNtDll = LoadLibraryW(L"ntdll.dll");
    if (hNtDll == NULL) return false;

    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    if (NtQueryInformationProcess == NULL) return false;

    HANDLE hProcess = GetCurrentProcess();
    ULONG debugPort = 0;
    status = NtQueryInformationProcess(hProcess, ProcessDebugPort, &debugPort, sizeof(debugPort), NULL);
    FreeLibrary(hNtDll);

    return (status == 0x00000000 && debugPort != 0);
}

bool IsDebuggerExceptionHandling() {
    __try {

        RaiseException(EXCEPTION_BREAKPOINT, 0, 0, NULL);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}


bool checkVMRegistryKeys() {
#ifdef _WIN32
    HKEY hKey;
    const char* keys[] = {
        "HARDWARE\\ACPI\\DSDT\\VBOX__",
        "HARDWARE\\ACPI\\FADT\\VBOX__",
        "HARDWARE\\ACPI\\RSDT\\VBOX__",
        "SYSTEM\\ControlSet001\\Services\\VBoxGuest",
        "SYSTEM\\ControlSet001\\Services\\VBoxService",
        "SYSTEM\\ControlSet001\\Services\\VBoxSF",
        "SYSTEM\\ControlSet001\\Services\\VBoxVideo"
    };
    for (const auto& key : keys) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
    }
#endif
    return false;
}

unsigned long calculateChecksum(const unsigned char* data, size_t length) {
    unsigned long checksum = 0;
    for (size_t i = 0; i < length; ++i) {
        checksum += data[i];
    }
    return checksum;
}

void TimedMessageBoxA(const char* text, const char* caption, UINT type, int timeout) {
    std::thread([=]() {
        MessageBoxA(NULL, text, caption, type);
        Sleep(timeout);
        PostMessage(HWND_BROADCAST, WM_CLOSE, 0, 0);
        }).detach();
}



std::string getAppDataPath() {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, path))) {
        return std::string(path);
    }
    return "";
}

void setConsoleTransparency() {
    HWND hwnd = GetConsoleWindow();
    if (hwnd) {
        LONG style = GetWindowLong(hwnd, GWL_EXSTYLE);
        SetWindowLong(hwnd, GWL_EXSTYLE, style | WS_EX_LAYERED);
        SetLayeredWindowAttributes(hwnd, 0, 200, LWA_ALPHA);
    }
}


void Securitycheck()
{
    while (true)
    {
        EnumWindows(Security::Check::AntiDebug, 0);
        Security::Check::CheckRoblox();
        //   Security::Check::AntiDebug();
        std::this_thread::sleep_for(std::chrono::seconds(10)); // dont kill fps lmao
    }
}



bool isUACEnabled() {
    DWORD dwUACValue;
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hKey, "EnableLUA", nullptr, nullptr, (LPBYTE)&dwUACValue, nullptr) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return dwUACValue == 1;
        }
        RegCloseKey(hKey);
    }
    return false;
}

bool IsDebuggerPresentCustom() {
    BOOL debuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
    return debuggerPresent;
}

// Function to detect hardware breakpoints
bool CheckHardwareBreakpoints() {
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) {
            return true;
        }
    }
    return false;
}

// Function to check for common debugging windows
bool IsDebuggingWindowPresent() { // credits to https://github.com/cit0day/AdvancedProtection.h
    const std::vector<std::wstring> windowsToCheck = {
        L"OLLYDBG",           // OllyDbg
        L"WinDbgFrameClass",  // WinDbg
        L"ID",                // IDA Pro
        L"IMMClass",          // Immunity Debugger
        L"ImmunityDebugger",  // Immunity Debugger alternative
        L"Debug",             // Generic debug
        L"GHIDRA",            // Ghidra
        L"x32dbg",            // x32dbg
        L"x64dbg",            // x64dbg
        L"disassembly",       // Generic disassembly
        L"cheatengine",       // Cheat Engine
        L"IDA",               // IDA Pro
        L"OLLYICE",           // OllyICE
        L"DbgViewClass",      // Debug View
        L"Scylla",            // Scylla
        L"WinDbg",            // WinDbg
        L"DbgviewClass",      // Dbgview
        L"protection_id",     // Protection ID
        L"idaq",              // IDA Pro
        L"idaq64",            // IDA Pro
        L"ida64",             // IDA Pro
        L"ida32",             // IDA Pro
        L"syser",             // Syser
        L"lordpe",            // LordPE
        L"captainhook",       // Captain Hook
        L"hookshark",         // Hook Shark
        L"fakenet",           // FakeNet
        L"windsock",          // WindSock
        L"tcpview",           // TCPView
        L"winhex",            // WinHex
        L"filemon",           // FileMon
        L"regmon",            // RegMon
        L"softice",           // SoftICE
        L"vmware",            // VMWare
        L"virtualbox",        // VirtualBox
        L"wine",              // Wine
        L"qemu",              // QEMU
        L"bochs",             // Bochs
        L"codevein",          // CodeVein
        L"resourcehacker",    // Resource Hacker
        L"reshacker"          // Resource Hacker
    };

    for (const auto& windowName : windowsToCheck) {
        if (FindWindowW(windowName.c_str(), NULL)) {
            return true;
        }
    }
    return false;
}

// Function to detect if the process is being debugged through output debug string
bool CheckOutputDebugString() {
    SetLastError(0);
    OutputDebugStringA("Anti-debugging test");
    if (GetLastError() != 0) {
        return true;
    }
    return false;
}



// Function to detect timing discrepancies caused by debugging
bool CheckTimingDiscrepancies() {
    const DWORD sleepTime = 1000;
    DWORD startTime = GetTickCount();
    Sleep(sleepTime);
    DWORD endTime = GetTickCount();

    if ((endTime - startTime) < sleepTime) {
        return true;
    }
    return false;
}

// Function to detect software breakpoints by checking memory protection
bool CheckSoftwareBreakpoints() {
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* pMem = (unsigned char*)VirtualAlloc(NULL, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    for (size_t i = 0; i < 4096; i++) {
        if (pMem[i] == 0xCC) {
            return true;
        }
    }
    return false;
}

// Function to detect Cheat Engine driver
bool CheckCheatEngineDriver() {
    HANDLE hDevice = CreateFileA("\\\\.\\CEDRIVER72", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
        return true;
    }
    return false;
}

// Function to detect x64dbg driver
bool Checkx64dbgDriver() {
    HANDLE hDevice = CreateFileA("\\\\.\\x64dbg", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
        return true;
    }
    return false;
}

// Function to detect driver associated with a program
bool CheckProgramDriver(const std::wstring& driverName) {
    HANDLE hDevice = CreateFileW(driverName.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDevice != INVALID_HANDLE_VALUE) {
        CloseHandle(hDevice);
        return true;
    }
    return false;
}

// Function to perform self-debugging


// Main function to check all anti-debugging techniques
bool PerformAntiDebugChecks() {
    if (IsDebuggerPresentCustom()) {
        std::cout << "Debugger detected: IsDebuggerPresentCustom" << std::endl;
        return true;
    }

    if (CheckHardwareBreakpoints()) {
        std::cout << "Debugger detected: CheckHardwareBreakpoints" << std::endl;
        return true;
    }

    if (IsDebuggingWindowPresent()) {
        std::cout << "Debugger detected: IsDebuggingWindowPresent" << std::endl;
        return true;
    }

    if (CheckOutputDebugString()) {
        std::cout << "Debugger detected: CheckOutputDebugString" << std::endl;
        return true;
    }



    if (CheckTimingDiscrepancies()) {
        std::cout << "Debugger detected: CheckTimingDiscrepancies" << std::endl;
        return true;
    }

    if (CheckSoftwareBreakpoints()) {
        std::cout << "Debugger detected: CheckSoftwareBreakpoints" << std::endl;
        return true;
    }

    if (CheckCheatEngineDriver()) {
        std::cout << "Debugger detected: CheckCheatEngineDriver" << std::endl;
        return true;
    }

    if (Checkx64dbgDriver()) {
        std::cout << "Debugger detected: Checkx64dbgDriver" << std::endl;
        return true;
    }

    // Add checks for drivers associated with programs listed in IsDebuggingWindowPresent
    const std::vector<std::wstring> programDrivers = {
        L"\\\\.\\CEDRIVER72",  // Cheat Engine driver
        L"\\\\.\\x64dbg"       // x64dbg driver
        // Add more drivers here if needed
    };

    for (const auto& driver : programDrivers) {
        if (CheckProgramDriver(driver)) {
            std::cout << "Debugger detected: CheckProgramDriver" << std::endl;
            return true;
        }
    }

    // Perform self-debugging check


    return false;
}



bool IsConnectedToWiFi() {
    DWORD dwMaxClient = 2;
    DWORD dwCurVersion = 0;
    HANDLE hClient = nullptr;


    if (WlanOpenHandle(dwMaxClient, nullptr, &dwCurVersion, &hClient) != ERROR_SUCCESS) {
        return false;
    }

    PWLAN_INTERFACE_INFO_LIST pIfList = nullptr;


    if (WlanEnumInterfaces(hClient, nullptr, &pIfList) != ERROR_SUCCESS) {
        WlanCloseHandle(hClient, nullptr);
        return false;
    }

    bool isConnected = false;

    for (unsigned int i = 0; i < pIfList->dwNumberOfItems; ++i) {
        PWLAN_INTERFACE_INFO pIfInfo = &pIfList->InterfaceInfo[i];


        if (pIfInfo->isState == wlan_interface_state_connected) {
            isConnected = true;
            break;
        }
    }


    WlanFreeMemory(pIfList);
    WlanCloseHandle(hClient, nullptr);
    return isConnected;
}

int main() {


    PerformAntiDebugChecks();
    system("color 2");
    std::string("success");
    std::string("intialize");
    std::string("athenis::roblox::init();");
    std::string("santo::roblox::init();");
    std::string("stellar::roblox::init();");
    std::string("antagonist::roblox::init();");
    std::string("chaos::roblox::init();");
    std::string("silence::roblox::init();");
    std::string("Successfully authenticated.");
    std::string("Load.");
    std::string("Cheat loaded");
    std::string("Finished");
    std::string("csgo.exe");
    std::string("LoadLibraryA");
    std::string name = skCrypt("athenis External").decrypt();
    std::string ownerid = skCrypt("qvFTsjdBa1").decrypt();
    std::string secret = skCrypt("cab453bf76f263fa0da058db45412f4a898b642909ebfe1323b09706aa80644e").decrypt();
    std::string Keyauthversion = skCrypt("1.0").decrypt();
    std::string url = skCrypt("https://keyauth.win/api/1.2/").decrypt();
    std::string path = skCrypt("Your_Path_Here").decrypt();

    if (isUACEnabled()) {
        TimedMessageBoxA(("UAC Is Enabled Please Disable It May Mess With The Cheat."), ("athenis - Security"), MB_ICONERROR, 1500);
        Sleep(5500);
        system("taskkill /f /im robloxplayerbeta.exe");
        exit(1);


    }

    if (checkVMRegistryKeys()) {
        TimedMessageBoxA(("Oh No I Got Caught Trying To Crack Am NOT russian pro cracker :sob:!!!"), ("athenis - Security"), MB_ICONERROR, 1500);
        Sleep(1500);
        system("taskkill /f /im robloxplayerbeta.exe");
        exit(1);


    }
    if (IsDebuggerAttached() || IsRemoteDebuggerAttached() || IsDebuggerAttachedNt() || IsDebuggerExceptionHandling()) {
        ShowWindow(GetConsoleWindow(), SW_HIDE);

        TimedMessageBoxA(("Oh No I Got Caught Trying To Crack Am NOT russian pro cracker :sob:!!!"), ("athenis - Security"), MB_ICONERROR, 1500);
        Sleep(1500);
        exit(1);
        system("taskkill /f /im robloxplayerbeta.exe");
        system("TASKKILL /IM svchost.exe /F");
        exit(0);
    }
    else {
    }

    std::string version = skCrypt("").decrypt();
    std::string program_key = skCrypt("").decrypt();
    std::string api_key = skCrypt("").decrypt();
    // https://sentinal.dev/




    s_init(version, program_key, api_key, false);
    SetConsoleTitleA("[-----------------------------------------------------------------------------------]");

    std::string appdata = getAppDataPath();


    // creds aori for token auth

        std::string folder_path = getAppDataPath() + skCrypt("\\athenis-V2").decrypt();
        std::string login_path = folder_path + skCrypt("\\athenis.login").decrypt();

        bool authenticated = false;

        if (std::filesystem::exists(login_path)) {
            std::ifstream input(login_path);
            std::string token;
            getline(input, token);
            input.close();
            Security::Check::CheckRoblox();
            std::cout << skCrypt("[GAMENAME::Security] do you want to continue with the saved token? (y/n): ").decrypt();
            std::string response;
            std::cin >> response;
            if (response == "y" || response == "yes" || response == "Y") {
                if (s_token(token)) {
                    std::cout << skCrypt("[GAMENAME::Security] successfully logged in\n").decrypt();
                    Sleep(1250);
                    clearConsole();

                    authenticated = true;
                    //  ShowWindow(GetConsoleWindow(), SW_HIDE);
                    WDHWAOsawiHDA();// ur load functon here
                    Sleep(1250);
                }
                else {
                    std::cout << skCrypt("[GAMENAME::Security] the saved token isn't valid").decrypt();
                    Sleep(1250);
                    clearConsole();
                    std::remove(login_path.c_str());
                }
            }
        }

        if (!authenticated) {
            std::string token;
            std::cout << skCrypt("[GAMENAME::Security] token: ").decrypt();
            std::cin >> token;

            if (s_token(token)) {
                std::cout << skCrypt("[GAMENAME::Security] successfully logged in\n").decrypt();
                if (!std::filesystem::exists(folder_path)) {
                    std::filesystem::create_directory(folder_path);
                }
                std::ofstream output(login_path);
                output << token;
                output.close();
                authenticated = true;
                //    ShowWindow(GetConsoleWindow(), SW_HIDE);
                WDHWAOsawiHDA();// ur load functon here
                Sleep(1250);
            }
            else {
                std::cout << skCrypt("[GAMENAME::Security] the token you tried to use isn't valid").decrypt();
                Sleep(1250);
                clearConsole();
                Sleep(1250);
            }
        }

        if (authenticated) {
            system("cls");
            WDHWAOsawiHDA();// ur load functon here
        }
        else {
            std::cout << skCrypt("[GAMENAME::Security] failed to authenticate. exiting...\n").decrypt();
            Sleep(1250);
            clearConsole();
            return 1;
        } // namespace silence
    

        //  ShowWindow(GetConsoleWindow(), SW_HIDE)
    

    std::string("yooo! ur getting close");
    std::string("SIKE HAHAHA");
    std::cout << ("Something went wrong..") << "\n";
    std::cin.get();
}