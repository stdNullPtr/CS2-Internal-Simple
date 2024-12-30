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
int wmain(int argc, wchar_t* argv[])
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

    std::filesystem::path argFilePath{argv[1]};
    if (!argFilePath.is_absolute())
    {
        argFilePath = absolute(argFilePath);
    }

    const std::wstring argTargetProcessName{argv[2]};
    bool manualMap{false};

    if (argc == 4)
    {
        std::wstring argIsManualMap{argv[3]};
        std::ranges::transform(argIsManualMap, argIsManualMap.begin(), ::towlower);
        manualMap = (argIsManualMap == L"true" || argIsManualMap == L"1");
    }

    wcout << XORW(L"File path: ") << argFilePath << '\n';
    wcout << XORW(L"Target process: ") << argTargetProcessName << '\n';
    wcout << XORW(L"Will we manual map?: ") << (manualMap ? XORW(L"yes") : XORW(L"no")) << '\n';

    const std::optional processId{commons::process::GetProcessIdByName(argTargetProcessName)};
    if (!processId)
    {
        wcerr << XORW(L"Failed to get target process ID.\n");
        return EXIT_FAILURE;
    }

    wcout << XORW(L"Process ID: ") << *processId << '\n';

    if (manualMap)
    {
        const std::optional fileContents{commons::file::ReadFile(argFilePath)};
        if (!fileContents)
        {
            wcerr << XORW(L"Failed to read file contents.\n");
            return EXIT_FAILURE;
        }
        if (!manual_map::MapDll(*processId, *fileContents))
        {
            wcerr << XORW(L"Manual mapping failed!\n");
            return EXIT_FAILURE;
        }
    }
    else
    {
        if (!load_library_map::InjectDllLoadLibrary(*processId, argFilePath))
        {
            wcerr << XORW(L"Injection failed!\n");
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
