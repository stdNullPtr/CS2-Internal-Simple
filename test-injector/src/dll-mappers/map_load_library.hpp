#pragma once
#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#include <iostream>
#include <string>
#include <xor.hpp>

namespace load_library_map
{
    using std::wcout, std::wcerr;

    inline bool inject_dll_load_library(const DWORD& process_id, const std::wstring& dll_full_path)
    {
        if (!process_id)
        {
            wcerr << XORW(L"Process ID is null?\n");
            return false;
        }

        const LPVOID load_library{(LPVOID)GetProcAddress(GetModuleHandle(XORW(L"KernelBase.dll")), XOR("LoadLibraryW"))};
        if (!load_library)
        {
            wcerr << XORW(L"GetProcAddress() failed: ") << GetLastError() << '\n';
            return false;
        }

        const HANDLE h_proc{
            OpenProcess(
                PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
                PROCESS_VM_READ, FALSE, process_id)
        };
        if (!h_proc)
        {
            wcerr << XORW(L"OpenProcess() failed: ") << GetLastError() << '\n';
            return false;
        }

        const LPVOID remote_string_allocated_mem{
            (VirtualAllocEx(h_proc, nullptr, dll_full_path.length(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE))
        };
        if (!remote_string_allocated_mem)
        {
            wcerr << XORW(L"VirtualAllocEx() failed: ") << GetLastError() << '\n';
            return false;
        }

        wcout << XORW(L"Remote string allocated memory: ") << remote_string_allocated_mem << '\n';

        if (!WriteProcessMemory(h_proc, remote_string_allocated_mem, dll_full_path.c_str(), dll_full_path.size() * sizeof(wchar_t), nullptr))
        {
            wcerr << XORW(L"WriteProcessMemory() failed: ") << GetLastError() << '\n';
            VirtualFreeEx(h_proc, remote_string_allocated_mem, 0, MEM_RELEASE);
            CloseHandle(h_proc);
            return false;
        }

        const HANDLE h_remote_thread{
            CreateRemoteThread(h_proc, nullptr, NULL, (LPTHREAD_START_ROUTINE)load_library, remote_string_allocated_mem, NULL, nullptr)
        };
        if (!h_remote_thread)
        {
            wcerr << XORW(L"CreateRemoteThread() failed: ") << GetLastError() << '\n';
            VirtualFreeEx(h_proc, remote_string_allocated_mem, 0, MEM_RELEASE);
            CloseHandle(h_proc);
            return false;
        }

        if (const DWORD wait_result{WaitForSingleObject(h_remote_thread, INFINITE)}; wait_result != WAIT_OBJECT_0)
        {
            wcerr << XORW(L"WaitForSingleObject() failed: ") << GetLastError() << '\n';
        }

        if (!CloseHandle(h_remote_thread))
        {
            wcerr << XORW(L"CloseHandle(hRemoteThread) failed: ") << GetLastError() << '\n';
        }

        VirtualFreeEx(h_proc, remote_string_allocated_mem, 0, MEM_RELEASE);
        CloseHandle(h_proc);

        return true;
    }
}
