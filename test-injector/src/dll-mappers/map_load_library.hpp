#pragma once
#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#include <iostream>
#include <string>
#include <xor.hpp>

namespace load_library_map
{
    using std::wcout, std::wcerr;

    inline bool InjectDllLoadLibrary(const DWORD& processId, const std::wstring& dllFullPath)
    {
        if (!processId)
        {
            wcerr << XORW(L"Process ID is null?\n");
            return false;
        }

        const LPVOID loadLibrary{(LPVOID)GetProcAddress(GetModuleHandle(XORW(L"KernelBase.dll")), XOR("LoadLibraryW"))};
        if (!loadLibrary)
        {
            wcerr << XORW(L"GetProcAddress() failed: ") << GetLastError() << '\n';
            return false;
        }

        const HANDLE hProc{
            OpenProcess(
                PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                PROCESS_VM_READ, FALSE, processId)
        };
        if (!hProc)
        {
            wcerr << XORW(L"OpenProcess() failed: ") << GetLastError() << '\n';
            return false;
        }

        const LPVOID remoteStringAllocatedMem{
            (VirtualAllocEx(hProc, nullptr, dllFullPath.length(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
        };
        if (!remoteStringAllocatedMem)
        {
            wcerr << XORW(L"VirtualAllocEx() failed: ") << GetLastError() << '\n';
            return false;
        }

        wcout << XORW(L"Remote string allocated memory: ") << remoteStringAllocatedMem << '\n';

        if (!WriteProcessMemory(hProc, remoteStringAllocatedMem, dllFullPath.c_str(), dllFullPath.size() * sizeof(wchar_t), nullptr))
        {
            wcerr << XORW(L"WriteProcessMemory() failed: ") << GetLastError() << '\n';
            VirtualFreeEx(hProc, remoteStringAllocatedMem, 0, MEM_RELEASE);
            CloseHandle(hProc);
            return false;
        }

        const HANDLE hRemoteThread{
            CreateRemoteThread(hProc, nullptr, NULL, (LPTHREAD_START_ROUTINE)loadLibrary, remoteStringAllocatedMem, NULL, nullptr)
        };
        if (!hRemoteThread)
        {
            wcerr << XORW(L"CreateRemoteThread() failed: ") << GetLastError() << '\n';
            VirtualFreeEx(hProc, remoteStringAllocatedMem, 0, MEM_RELEASE);
            CloseHandle(hProc);
            return false;
        }

        const DWORD waitResult{WaitForSingleObject(hRemoteThread, INFINITE)};
        if (waitResult != WAIT_OBJECT_0)
        {
            wcerr << XORW(L"WaitForSingleObject() failed: ") << GetLastError() << '\n';
        }

        if (!CloseHandle(hRemoteThread))
        {
            wcerr << XORW(L"CloseHandle(hRemoteThread) failed: ") << GetLastError() << '\n';
        }

        VirtualFreeEx(hProc, remoteStringAllocatedMem, 0, MEM_RELEASE);
        CloseHandle(hProc);

        return true;
    }
}
