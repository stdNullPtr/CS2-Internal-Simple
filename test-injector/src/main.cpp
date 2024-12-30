#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <conio.h>
#include <xor.hpp>
#include "dll-mappers/map_manual.hpp"
#include "file.hpp"
#include "process.hpp"
#include "dll-mappers/map_load_library.hpp"

using std::wcout, std::wcerr;

/**
 * If it is a 64-bit process, compile and run in 64bit:
 * https://stackoverflow.com/questions/9456228/createremotethread-returning-error-access-denied-windows-7-dll-injection
 ***/
int wmain(const int argc, const wchar_t* const argv[])
{
    if (argc < 3 || argc > 4)
    {
        wcerr << XORW(L"Usage: ") << argv[0] << XORW(L" <DLL file path> <Target process name> [manual map: true/false (optional, default: false)]\n")
            << XORW(L"\nArguments:\n")
            << XORW(L"  <DLL file path>          Path to the DLL you want to inject.\n")
            << XORW(L"  <Target process name>    Name of the target process.\n")
            << XORW(L"  [manual map]             Optional boolean flag (true/false) to indicate if manual mapping is required.\n")
            << XORW(L"                           Defaults to false if not provided.\n");
        return EXIT_FAILURE;
    }

    std::filesystem::path arg_file_path{argv[1]};
    if (!arg_file_path.is_absolute())
    {
        arg_file_path = absolute(arg_file_path);
    }

    const std::wstring arg_target_process_name{argv[2]};
    bool manual_map{false};

    if (argc == 4)
    {
        std::wstring arg_is_manual_map{argv[3]};
        std::ranges::transform(arg_is_manual_map, arg_is_manual_map.begin(), ::towlower);
        manual_map = arg_is_manual_map == XORW(L"true") || arg_is_manual_map == XORW(L"1");
    }

    wcout << XORW(L"File path: ") << arg_file_path << '\n';
    wcout << XORW(L"Target process: ") << arg_target_process_name << '\n';
    wcout << XORW(L"Will we manual map?: ") << (manual_map ? XORW(L"yes") : XORW(L"no")) << '\n';

    const std::optional process_id{commons::process::get_process_id_by_name(arg_target_process_name)};
    if (!process_id)
    {
        wcerr << XORW(L"Failed to get target process ID.\n");
        return EXIT_FAILURE;
    }

    wcout << XORW(L"Process ID: ") << *process_id << '\n';

    if (manual_map)
    {
        const std::optional file_contents{commons::file::read_file(arg_file_path)};
        if (!file_contents)
        {
            wcerr << XORW(L"Failed to read file contents.\n");
            return EXIT_FAILURE;
        }
        if (!manual_map::map_dll(*process_id, *file_contents))
        {
            wcerr << XORW(L"Manual mapping failed!\n");
            return EXIT_FAILURE;
        }
    }
    else
    {
        if (!load_library_map::inject_dll_load_library(*process_id, arg_file_path))
        {
            wcerr << XORW(L"Injection failed!\n");
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
