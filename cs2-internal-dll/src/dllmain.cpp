#define WIN32_LEAN_AND_MEAN  
#include <windows.h>
#ifndef NDEBUG
#include "console.hpp"
#include <string>
#endif
#include "xor.hpp"
#include <thread>
#include <sstream>
#include "global.hpp"
#include "logger.hpp"
#include "keyboard.hpp"

static_assert(sizeof(uintptr_t) == 8, "Expected 64-bit environment");

using commons::logger::log;
using std::this_thread::sleep_for;
using namespace std::chrono_literals;

DWORD WINAPI main_routine(LPVOID h_module)
{
#ifndef NDEBUG
    commons::console::init_console();
    commons::console::set_cursor_visibility(false);
#endif

    const auto client_dll_base{reinterpret_cast<uintptr_t>(GetModuleHandle(g::client_dll_module_name.c_str()))};

    while (!commons::keyboard::is_key_pressed(VK_END))
    {
#ifndef NDEBUG
        commons::console::clear_console({0, 0});
#endif
        log(XORW(L"Base address: '0x%llX' press END to exit\n"), h_module);
        log(XORW(L"client.dll: '0x%llX'\n"), client_dll_base);

        if (!client_dll_base)
        {
            log(XORW(L"client.dll not found, will exit in 5 secs\n"));
            Sleep(5 * 1000);
            break;
        }

        sleep_for(10ms);
    }

#ifndef NDEBUG
    commons::console::destroy_console();
#endif

    // *Comment is for manual mapping*
    // TODO: this is potentially bad since we definitely did not manually map in a perfect way like the Windows loader does, so we can't rely on it to unload
    // It definitely does not work currently and the bytes are left in memory.
    FreeLibraryAndExitThread(static_cast<HMODULE>(h_module), 0);
}

void handle_error(const std::wstring& msg)
{
    std::wostringstream s;
    s << msg << XORW(L"\nError code: ") << GetLastError();

#ifndef NDEBUG
    log(s.str());
#else
    MessageBox(NULL, s.str().c_str(), XORW(L"Error"), MB_OK);
#endif
}

// Important: DO NOT CHANGE SIGNATURE/NAMING CONVENTION of this function
// ReSharper disable once CppInconsistentNaming
BOOL WINAPI DllMain(HINSTANCE h_module, DWORD fdw_reason, [[maybe_unused]] LPVOID lp_reserved)
{
    if (fdw_reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(h_module);
        CloseHandle(CreateThread(nullptr, NULL, main_routine, h_module, NULL, nullptr));
    }

    return TRUE;
}