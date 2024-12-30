#pragma once
#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#include <iostream>
#include <string>
#include <xor.hpp>
#include <vector>

namespace manual_map
{
    using std::wcout, std::wcerr;

    namespace internal
    {
        using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
        using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
        using f_DllEntryPoint = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);

        struct MANUAL_MAPPING_DATA
        {
            f_LoadLibraryA pLoadLibraryA;
            f_GetProcAddress pGetProcAddress;
            BYTE* pbase;
            DWORD dwCheck;
        };
    }

    template <typename... Pointers>
    void VirtualFreeExMultipleAndCloseHandle(const HANDLE& hProc, const Pointers&... pMem)
    {
        (..., VirtualFreeEx(hProc, pMem, 0, MEM_RELEASE));
        CloseHandle(hProc);
    }

    inline void __stdcall Shellcode(internal::MANUAL_MAPPING_DATA* pData)
    {
#define RELOC_FLAG32(RelInfo) (((RelInfo) >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) (((RelInfo) >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

        if (!pData)
        {
            return;
        }

        if (!pData->pGetProcAddress || !pData->pLoadLibraryA || !pData->pbase)
        {
            pData->dwCheck = (DWORD)0x40404040;
            return;
        }

        BYTE* pBase{pData->pbase};
        const IMAGE_DOS_HEADER* pDosHeader{(IMAGE_DOS_HEADER*)pBase};
        const IMAGE_NT_HEADERS* pNtHeader{(IMAGE_NT_HEADERS*)(pBase + pDosHeader->e_lfanew)};
        const IMAGE_OPTIONAL_HEADER64* pOptionalHeader{&pNtHeader->OptionalHeader};

        const internal::f_LoadLibraryA fLoadLibraryA{pData->pLoadLibraryA};
        const internal::f_GetProcAddress fGetProcAddress{pData->pGetProcAddress};

        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            pData->dwCheck = (DWORD)0x40404041;
            return;
        }
        if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
        {
            pData->dwCheck = (DWORD)0x40404042;
            return;
        }
        if (pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
        {
            pData->dwCheck = (DWORD)0x40404043;
            return;
        }

        const auto fDllMain{(internal::f_DllEntryPoint)(pBase + pOptionalHeader->AddressOfEntryPoint)};

        if (BYTE* locationDelta = pBase - pOptionalHeader->ImageBase)
        {
            if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
            {
                auto* pRelocData{
                    (IMAGE_BASE_RELOCATION*)(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].
                        VirtualAddress)
                };
                const auto* pRelocEnd{
                    (IMAGE_BASE_RELOCATION*)((uintptr_t)pRelocData + pOptionalHeader->DataDirectory[
                        IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
                };
                while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock)
                {
                    const UINT numEntries{(UINT)((pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD))};
                    WORD* pRelativeInfo{(WORD*)(pRelocData + 1)};

                    for (UINT i{0}; i != numEntries; ++i, ++pRelativeInfo)
                    {
                        if (RELOC_FLAG(*pRelativeInfo))
                        {
                            UINT_PTR* pPatch{(UINT_PTR*)(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF))};
                            *pPatch += (UINT_PTR)locationDelta;
                        }
                    }
                    pRelocData = (IMAGE_BASE_RELOCATION*)((BYTE*)pRelocData + pRelocData->SizeOfBlock);
                }
            }
        }

        if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
        {
            auto* pImportDescr{
                (IMAGE_IMPORT_DESCRIPTOR*)(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].
                    VirtualAddress)
            };
            while (pImportDescr->Name)
            {
                const char* name{(char*)(pBase + pImportDescr->Name)};
                const HINSTANCE hDll{fLoadLibraryA(name)};

                ULONG_PTR* pThunkRef{(ULONG_PTR*)(pBase + pImportDescr->OriginalFirstThunk)};
                ULONG_PTR* pFuncRef{(ULONG_PTR*)(pBase + pImportDescr->FirstThunk)};

                if (!pThunkRef)
                {
                    pThunkRef = pFuncRef;
                }

                for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
                {
                    if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
                    {
                        *pFuncRef = (ULONG_PTR)fGetProcAddress(hDll, (char*)(*pThunkRef & 0xFFFF));
                    }
                    else
                    {
                        const auto* pImport{(IMAGE_IMPORT_BY_NAME*)(pBase + *pThunkRef)};
                        *pFuncRef = (ULONG_PTR)fGetProcAddress(hDll, pImport->Name);
                    }
                }
                ++pImportDescr;
            }
        }

        if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
        {
            const auto* pTls{
                (IMAGE_TLS_DIRECTORY*)(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress)
            };
            const auto* pCallback{(PIMAGE_TLS_CALLBACK*)pTls->AddressOfCallBacks};
            for (; pCallback && *pCallback; ++pCallback)
                (*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
        }

        // TODO: can we use lpReserved to somehow monitor the thread from outside and wipe it with loader? We don't have a proper way to unload.
        fDllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

        pData->dwCheck = (DWORD)0x10101010;
    }

    inline bool MapDll(const DWORD& processId, const std::vector<char>& fileContents)
    {
#ifndef NDEBUG
        wcerr << XORW(L"You cannot manual map in a debug build, the shellcode will contain non-portable instructions.\n");
        return false;
#endif

        if (!processId)
        {
            wcerr << XORW(L"Process ID is null?\n");
            return false;
        }

        const auto* const pFileContents{fileContents.data()};

        auto hexWStr = [](const auto& value)
        {
            std::wstringstream ss;
            ss << std::hex << XORW(L"0x") << std::uppercase << value;
            return ss.str();
        };

        auto hexStr = [](const auto& value)
        {
            std::stringstream ss;
            ss << std::hex << XOR("0x") << std::uppercase << value;
            return ss.str();
        };

        const auto* const pDosHeader{(PIMAGE_DOS_HEADER)pFileContents};
        if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        {
            wcerr << XORW(L"DOS header begins with an invalid WORD: ") << hexWStr(pDosHeader->e_magic) << XORW(L" should be: ") << hexWStr(IMAGE_DOS_SIGNATURE) << '\n';
            return false;
        }

        const auto* const pPeHeaders{(PIMAGE_NT_HEADERS)(pFileContents + pDosHeader->e_lfanew)};
        if (pPeHeaders->Signature != IMAGE_NT_SIGNATURE)
        {
            wcerr << XORW(L"PE header begins with an invalid LONG sig: ") << hexWStr(pPeHeaders->Signature) << XORW(L" should be: ") << hexWStr(IMAGE_NT_SIGNATURE) << '\n';
            return false;
        }

#ifdef _WIN64
        if (pPeHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        {
            wcerr << XORW(L"Invalid target platform of the DLL, expected IMAGE_FILE_MACHINE_AMD64\n");
            return false;
        }
#else
        if (pPeHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
        {
            wcerr << XORW(L"Invalid target platform of the DLL, expected IMAGE_FILE_MACHINE_I386\n");
            return false;
        }
#endif

        const auto* const pSectionHeaders{IMAGE_FIRST_SECTION(pPeHeaders)};

        const HANDLE hProc{OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, processId)};
        if (!hProc)
        {
            wcerr << XORW(L"OpenProcess() failed: ") << GetLastError() << '\n';
            return false;
        }

        const LPVOID pTargetBase{
            VirtualAllocEx(hProc,
                           nullptr,
                           pPeHeaders->OptionalHeader.SizeOfImage,
                           MEM_COMMIT | MEM_RESERVE,
                           PAGE_EXECUTE_READWRITE)
        };

        if (!pTargetBase)
        {
            wcerr << XORW(L"VirtualAllocEx() failed: [") << GetLastError() << XORW(L"] exiting...\n");
            CloseHandle(hProc);
            return false;
        }

        if (!WriteProcessMemory(hProc, pTargetBase, pFileContents, 0x1000, nullptr))
        {
            wcerr << XORW(L"WriteProcessMemory() failed, can't write file header: [") << GetLastError() << XORW(L"] exiting...\n");
            VirtualFreeExMultipleAndCloseHandle(hProc, pTargetBase);
            return false;
        }

        for (auto i{0}; i < pPeHeaders->FileHeader.NumberOfSections; i++)
        {
            const IMAGE_SECTION_HEADER section{pSectionHeaders[i]};
            if (section.PointerToRawData)
            {
                if (!WriteProcessMemory(hProc,
                                        (BYTE*)pTargetBase + section.VirtualAddress,
                                        pFileContents + section.PointerToRawData,
                                        section.SizeOfRawData,
                                        nullptr))
                {
                    wcerr << XORW(L"WriteProcessMemory() failed writing section number: [") << i << XORW(L"] error:[") << GetLastError() << XORW(L"] exiting...\n");
                    VirtualFreeExMultipleAndCloseHandle(hProc, pTargetBase);
                    return false;
                }
            }
        }

        internal::MANUAL_MAPPING_DATA manualMapData;
        manualMapData.pLoadLibraryA = LoadLibraryA;
        manualMapData.pGetProcAddress = GetProcAddress;
        manualMapData.pbase = (BYTE*)pTargetBase;
        manualMapData.dwCheck = 0x0;

        const LPVOID pTargetMappingData{
            VirtualAllocEx(hProc, nullptr, sizeof(internal::MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        };
        if (!pTargetMappingData)
        {
            wcerr << XORW(L"VirtualAllocEx() for target mapping data failed: [") << GetLastError() << XORW(L"] exiting...\n");
            VirtualFreeExMultipleAndCloseHandle(hProc, pTargetBase);
            return false;
        }

        if (!WriteProcessMemory(hProc, pTargetMappingData, &manualMapData, sizeof(internal::MANUAL_MAPPING_DATA), nullptr))
        {
            wcerr << XORW(L"WriteProcessMemory() for target mapping data failed: [") << GetLastError() << XORW(L"] exiting...\n");
            VirtualFreeExMultipleAndCloseHandle(hProc, pTargetBase, pTargetMappingData);
            return false;
        }

        const LPVOID pShellcode{VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)};
        if (!pShellcode)
        {
            wcerr << XORW(L"VirtualAllocEx() for shellcode failed: [") << GetLastError() << XORW(L"] exiting...\n");
            VirtualFreeExMultipleAndCloseHandle(hProc, pTargetBase, pTargetMappingData);
            return false;
        }

        wcout << XORW(L"My shellcode pointer: ") << hexWStr(Shellcode) << '\n';
        wcout << XORW(L"Target shellcode: ") << hexWStr(pShellcode) << '\n';
        wcout << XORW(L"Target data: ") << hexWStr(pTargetMappingData) << '\n';
        wcout << XORW(L"Target base: ") << hexWStr(pTargetBase) << '\n';

        if (!WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr))
        {
            wcerr << XORW(L"WriteProcessMemory() for shellcode failed: [") << GetLastError() << XORW(L"] exiting...\n");
            VirtualFreeExMultipleAndCloseHandle(hProc, pTargetBase, pTargetMappingData, pShellcode);
            return false;
        }

        const HANDLE hThread{
            CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)pShellcode, pTargetMappingData, 0, nullptr)
        };
        if (!hThread)
        {
            wcerr << XORW(L"CreateRemoteThread() failed: [") << GetLastError() << XORW(L"] exiting...\n");
            VirtualFreeExMultipleAndCloseHandle(hProc, pTargetBase, pTargetMappingData, pShellcode);
            return false;
        }
        CloseHandle(hThread);

        wcout << XORW(L"Starting mapping validation...\n");

        while (true)
        {
            DWORD exitCode{0};
            GetExitCodeProcess(hProc, &exitCode);
            if (exitCode != STILL_ACTIVE)
            {
                wcerr << XORW(L"Process crashed, exit code: dec: ") << exitCode << XORW(L" hex: ") << hexWStr(exitCode) << '\n';
                return false;
            }

            internal::MANUAL_MAPPING_DATA dataCheck;
            if (!ReadProcessMemory(hProc, pTargetMappingData, &dataCheck, sizeof internal::MANUAL_MAPPING_DATA, nullptr))
            {
                wcerr << XORW(L"ReadProcessMemory() for final check failed: [") << GetLastError() << XORW(L"] exiting...\n");
                VirtualFreeExMultipleAndCloseHandle(hProc, pTargetBase, pTargetMappingData, pShellcode);
                return false;
            }

            if (dataCheck.dwCheck == (DWORD)0x40404040)
            {
                wcerr << XORW(L"Wrong/null function argument for the shellcode, exiting...\n");
                VirtualFreeExMultipleAndCloseHandle(hProc, pTargetBase, pTargetMappingData, pShellcode);
                return false;
            }

            if (dataCheck.dwCheck == (DWORD)0x40404041 || dataCheck.dwCheck == (DWORD)0x40404042 || dataCheck.dwCheck == (DWORD)0x40404043)
            {
                wcerr << XORW(L"Fail in shellcode: ") << hexWStr(dataCheck.dwCheck) << '\n';
                VirtualFreeExMultipleAndCloseHandle(hProc, pTargetBase, pTargetMappingData, pShellcode);
                return false;
            }

            if (dataCheck.dwCheck == (DWORD)0x10101010)
            {
                wcout << XORW(L"Success, shellcode has completed, final check value: ") << hexWStr(dataCheck.dwCheck) << '\n';
                break;
            }

            wcout << XORW(L"Waiting for shellcode completion, current check: ") << hexWStr(dataCheck.dwCheck) << '\n';
            Sleep(500);
        }

        // wipe PE headers
        const std::vector<uint8_t> emptyBuffer(0x1000, 0);
        WriteProcessMemory(hProc, pTargetBase, emptyBuffer.data(), emptyBuffer.size(), nullptr);

        for (auto i{0}; i < pPeHeaders->FileHeader.NumberOfSections; i++)
        {
            const IMAGE_SECTION_HEADER section{pSectionHeaders[i]};
            if (section.Misc.VirtualSize)
            {
                DWORD oldProtection{0};
                DWORD newProtection{PAGE_READONLY};

                if ((section.Characteristics & IMAGE_SCN_MEM_WRITE) > 0)
                {
                    newProtection = PAGE_READWRITE;
                }
                else if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0)
                {
                    newProtection = PAGE_EXECUTE_READ;
                }
                if (VirtualProtectEx(hProc, (BYTE*)pTargetBase + section.VirtualAddress, section.Misc.VirtualSize, newProtection, &oldProtection))
                {
                    std::cout << XOR("Section ") << std::string((char*)section.Name, 8) << XOR(" set as: ") << hexStr(newProtection) << '\n';
                }
                else
                {
                    std::cerr << XOR("FAIL: Section ") << std::string((char*)section.Name, 8) << XOR(" not set as: ") << hexStr(newProtection) << '\n';
                }
            }
        }
        DWORD old{0};
        VirtualProtectEx(hProc, pTargetBase, pSectionHeaders->VirtualAddress, PAGE_READONLY, &old);

        VirtualFreeExMultipleAndCloseHandle(hProc, pTargetMappingData, pShellcode);

        return true;
    }
}
