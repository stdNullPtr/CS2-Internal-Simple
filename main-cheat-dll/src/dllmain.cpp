#define WIN32_LEAN_AND_MEAN  
#include <windows.h>
#ifndef NDEBUG
#include "console.hpp"
#include <iostream>
#include <format>
#include <string>
#endif
#include "xor.hpp"
#include <thread>
#include <sstream>

static_assert(sizeof(uintptr_t) == 8, "Expected 64-bit environment");

#ifndef NDEBUG
template <typename... Args>
void LOG(const std::wstring& fmt, Args&&... args)
{
    wprintf(fmt.c_str(), std::forward<Args>(args)...);
}

#else
#define LOG(...)
#endif

void HandleError(const std::wstring& msg);
DWORD WINAPI MainRoutine(LPVOID hModule);

BOOL WINAPI DllMain(HINSTANCE hModule, DWORD fdwReason, [[maybe_unused]] LPVOID lpReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(nullptr, NULL, MainRoutine, hModule, NULL, nullptr);
        break;
    case DLL_THREAD_ATTACH: break;
    case DLL_THREAD_DETACH: break;
    case DLL_PROCESS_DETACH: break;
    }
    return TRUE;
}

void HandleError(const std::wstring& msg)
{
    std::wostringstream s;
    s << msg << XORW(L"\nError code: ") << GetLastError();

#ifndef NDEBUG
    std::wcout << s.str();
#else
    MessageBox(NULL, s.str().c_str(), XORW(L"Error"), MB_OK);
#endif
}

DWORD WINAPI MainRoutine(LPVOID hModule)
{
#ifndef NDEBUG
    commons::console::initConsole();
    commons::console::setCursorVisibility(false);
#endif

    const auto clientDllBase{reinterpret_cast<uintptr_t>(GetModuleHandle(XORW(L"client.dll")))};

    while (!(GetAsyncKeyState(VK_END) & 0x1))
    {
        LOG(XORW(L"Base address: '0x%llX' press END to exit\n"), reinterpret_cast<uint64_t>(hModule));
        Sleep(10);
    }

#ifndef NDEBUG
    commons::console::destroyConsole();
#endif

    // TODO: this is potentially bad since we definitely did not manually map in a perfect way like the Windows loader does, so we can't rely on it to unload
    // It definitely does not work currently and the bytes are left in memory.
    FreeLibraryAndExitThread(static_cast<HMODULE>(hModule), 0);
}
