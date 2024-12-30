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
        using f_load_library_a = HINSTANCE(WINAPI*)(const char* lp_lib_filename);
        using f_get_proc_address = FARPROC(WINAPI*)(HMODULE h_module, LPCSTR lp_proc_name);
        using f_dll_entry_point = BOOL(WINAPI*)(void* h_dll, DWORD dw_reason, void* p_reserved);

        struct manual_mapping_data
        {
            f_load_library_a p_load_library_a;
            f_get_proc_address p_get_proc_address;
            BYTE* p_base;
            DWORD dw_check;
        };
    }

    template <typename... Pointers>
    void virtual_free_ex_multiple_and_close_handle(const HANDLE& h_proc, const Pointers&... p_mem)
    {
        (..., VirtualFreeEx(h_proc, p_mem, 0, MEM_RELEASE));
        CloseHandle(h_proc);
    }

    inline void __stdcall shellcode(internal::manual_mapping_data* p_data)
    {
#define RELOC_FLAG32(RelInfo) (((RelInfo) >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) (((RelInfo) >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

        if (!p_data)
        {
            return;
        }

        if (!p_data->p_get_proc_address || !p_data->p_load_library_a || !p_data->p_base)
        {
            p_data->dw_check = (DWORD)0x40404040;
            return;
        }

        BYTE* p_base{p_data->p_base};
        const IMAGE_DOS_HEADER* p_dos_header{(IMAGE_DOS_HEADER*)p_base};
        const IMAGE_NT_HEADERS* p_nt_header{(IMAGE_NT_HEADERS*)(p_base + p_dos_header->e_lfanew)};
        const IMAGE_OPTIONAL_HEADER64* p_optional_header{&p_nt_header->OptionalHeader};

        const internal::f_load_library_a f_load_library_a{p_data->p_load_library_a};
        const internal::f_get_proc_address f_get_proc_address{p_data->p_get_proc_address};

        if (p_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
        {
            p_data->dw_check = (DWORD)0x40404041;
            return;
        }
        if (p_nt_header->Signature != IMAGE_NT_SIGNATURE)
        {
            p_data->dw_check = (DWORD)0x40404042;
            return;
        }
        if (p_nt_header->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC)
        {
            p_data->dw_check = (DWORD)0x40404043;
            return;
        }

        const auto f_dll_main{(internal::f_dll_entry_point)(p_base + p_optional_header->AddressOfEntryPoint)};

        if (BYTE* location_delta = p_base - p_optional_header->ImageBase)
        {
            if (p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
            {
                auto* p_reloc_data{
                    (IMAGE_BASE_RELOCATION*)(p_base + p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].
                        VirtualAddress)
                };
                const auto* p_reloc_end{
                    (IMAGE_BASE_RELOCATION*)((uintptr_t)p_reloc_data + p_optional_header->DataDirectory[
                        IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
                };
                while (p_reloc_data < p_reloc_end && p_reloc_data->SizeOfBlock)
                {
                    const UINT num_entries{(UINT)((p_reloc_data->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD))};
                    WORD* p_relative_info{(WORD*)(p_reloc_data + 1)};

                    for (UINT i{0}; i != num_entries; ++i, ++p_relative_info)
                    {
                        if (RELOC_FLAG(*p_relative_info))
                        {
                            UINT_PTR* p_patch{(UINT_PTR*)(p_base + p_reloc_data->VirtualAddress + ((*p_relative_info) & 0xFFF))};
                            *p_patch += (UINT_PTR)location_delta;
                        }
                    }
                    p_reloc_data = (IMAGE_BASE_RELOCATION*)((BYTE*)p_reloc_data + p_reloc_data->SizeOfBlock);
                }
            }
        }

        if (p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
        {
            auto* p_import_descriptor{
                (IMAGE_IMPORT_DESCRIPTOR*)(p_base + p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].
                    VirtualAddress)
            };
            while (p_import_descriptor->Name)
            {
                const char* name{(char*)(p_base + p_import_descriptor->Name)};
                const HINSTANCE h_dll{f_load_library_a(name)};

                ULONG_PTR* p_thunk_ref{(ULONG_PTR*)(p_base + p_import_descriptor->OriginalFirstThunk)};
                ULONG_PTR* p_func_ref{(ULONG_PTR*)(p_base + p_import_descriptor->FirstThunk)};

                if (!p_thunk_ref)
                {
                    p_thunk_ref = p_func_ref;
                }

                for (; *p_thunk_ref; ++p_thunk_ref, ++p_func_ref)
                {
                    if (IMAGE_SNAP_BY_ORDINAL(*p_thunk_ref))
                    {
                        *p_func_ref = (ULONG_PTR)f_get_proc_address(h_dll, (char*)(*p_thunk_ref & 0xFFFF));
                    }
                    else
                    {
                        const auto* p_import{(IMAGE_IMPORT_BY_NAME*)(p_base + *p_thunk_ref)};
                        *p_func_ref = (ULONG_PTR)f_get_proc_address(h_dll, p_import->Name);
                    }
                }
                ++p_import_descriptor;
            }
        }

        if (p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
        {
            const auto* p_tls{
                (IMAGE_TLS_DIRECTORY*)(p_base + p_optional_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress)
            };
            const auto* p_callback{(PIMAGE_TLS_CALLBACK*)p_tls->AddressOfCallBacks};
            for (; p_callback && *p_callback; ++p_callback)
                (*p_callback)(p_base, DLL_PROCESS_ATTACH, nullptr);
        }

        // TODO: can we use lpReserved to somehow monitor the thread from outside and wipe it with loader? We don't have a proper way to unload.
        f_dll_main(p_base, DLL_PROCESS_ATTACH, nullptr);

        p_data->dw_check = (DWORD)0x10101010;
    }

    inline bool map_dll(const DWORD& process_id, const std::vector<char>& file_contents)
    {
#ifndef NDEBUG
        wcerr << XORW(L"You cannot manual map in a debug build, the shellcode will contain non-portable instructions.\n");
        return false;
#endif

        if (!process_id)
        {
            wcerr << XORW(L"Process ID is null?\n");
            return false;
        }

        const auto* const p_file_contents{file_contents.data()};

        auto hex_w_str = [](const auto& value)
        {
            std::wstringstream ss;
            ss << std::hex << XORW(L"0x") << std::uppercase << value;
            return ss.str();
        };

        auto hex_str = [](const auto& value)
        {
            std::stringstream ss;
            ss << std::hex << XOR("0x") << std::uppercase << value;
            return ss.str();
        };

        const auto* const p_dos_header{(PIMAGE_DOS_HEADER)p_file_contents};
        if (p_dos_header->e_magic != IMAGE_DOS_SIGNATURE)
        {
            wcerr << XORW(L"DOS header begins with an invalid WORD: ") << hex_w_str(p_dos_header->e_magic) << XORW(L" should be: ") << hex_w_str(IMAGE_DOS_SIGNATURE) << '\n';
            return false;
        }

        const auto* const p_pe_headers{(PIMAGE_NT_HEADERS)(p_file_contents + p_dos_header->e_lfanew)};
        if (p_pe_headers->Signature != IMAGE_NT_SIGNATURE)
        {
            wcerr << XORW(L"PE header begins with an invalid LONG sig: ") << hex_w_str(p_pe_headers->Signature) << XORW(L" should be: ") << hex_w_str(IMAGE_NT_SIGNATURE) << '\n';
            return false;
        }

#ifdef _WIN64
        if (p_pe_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
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

        const auto* const p_section_headers{IMAGE_FIRST_SECTION(p_pe_headers)};

        const HANDLE h_proc{OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, process_id)};
        if (!h_proc)
        {
            wcerr << XORW(L"OpenProcess() failed: ") << GetLastError() << '\n';
            return false;
        }

        const LPVOID p_target_base{
            VirtualAllocEx(h_proc,
                           nullptr,
                           p_pe_headers->OptionalHeader.SizeOfImage,
                           MEM_COMMIT | MEM_RESERVE,
                           PAGE_EXECUTE_READWRITE)
        };

        if (!p_target_base)
        {
            wcerr << XORW(L"VirtualAllocEx() failed: [") << GetLastError() << XORW(L"] exiting...\n");
            CloseHandle(h_proc);
            return false;
        }

        if (!WriteProcessMemory(h_proc, p_target_base, p_file_contents, 0x1000, nullptr))
        {
            wcerr << XORW(L"WriteProcessMemory() failed, can't write file header: [") << GetLastError() << XORW(L"] exiting...\n");
            virtual_free_ex_multiple_and_close_handle(h_proc, p_target_base);
            return false;
        }

        for (auto i{0}; i < p_pe_headers->FileHeader.NumberOfSections; i++)
        {
            const IMAGE_SECTION_HEADER section{p_section_headers[i]};
            if (section.PointerToRawData)
            {
                if (!WriteProcessMemory(h_proc,
                                        (BYTE*)p_target_base + section.VirtualAddress,
                                        p_file_contents + section.PointerToRawData,
                                        section.SizeOfRawData,
                                        nullptr))
                {
                    wcerr << XORW(L"WriteProcessMemory() failed writing section number: [") << i << XORW(L"] error:[") << GetLastError() << XORW(L"] exiting...\n");
                    virtual_free_ex_multiple_and_close_handle(h_proc, p_target_base);
                    return false;
                }
            }
        }

        internal::manual_mapping_data manual_map_data;
        manual_map_data.p_load_library_a = LoadLibraryA;
        manual_map_data.p_get_proc_address = GetProcAddress;
        manual_map_data.p_base = (BYTE*)p_target_base;
        manual_map_data.dw_check = 0x0;

        const LPVOID p_target_mapping_data{
            VirtualAllocEx(h_proc, nullptr, sizeof(internal::manual_mapping_data), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        };
        if (!p_target_mapping_data)
        {
            wcerr << XORW(L"VirtualAllocEx() for target mapping data failed: [") << GetLastError() << XORW(L"] exiting...\n");
            virtual_free_ex_multiple_and_close_handle(h_proc, p_target_base);
            return false;
        }

        if (!WriteProcessMemory(h_proc, p_target_mapping_data, &manual_map_data, sizeof(internal::manual_mapping_data), nullptr))
        {
            wcerr << XORW(L"WriteProcessMemory() for target mapping data failed: [") << GetLastError() << XORW(L"] exiting...\n");
            virtual_free_ex_multiple_and_close_handle(h_proc, p_target_base, p_target_mapping_data);
            return false;
        }

        const LPVOID p_shellcode{VirtualAllocEx(h_proc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)};
        if (!p_shellcode)
        {
            wcerr << XORW(L"VirtualAllocEx() for shellcode failed: [") << GetLastError() << XORW(L"] exiting...\n");
            virtual_free_ex_multiple_and_close_handle(h_proc, p_target_base, p_target_mapping_data);
            return false;
        }

        wcout << XORW(L"My shellcode pointer: ") << hex_w_str(shellcode) << '\n';
        wcout << XORW(L"Target shellcode: ") << hex_w_str(p_shellcode) << '\n';
        wcout << XORW(L"Target data: ") << hex_w_str(p_target_mapping_data) << '\n';
        wcout << XORW(L"Target base: ") << hex_w_str(p_target_base) << '\n';

        if (!WriteProcessMemory(h_proc, p_shellcode, shellcode, 0x1000, nullptr))
        {
            wcerr << XORW(L"WriteProcessMemory() for shellcode failed: [") << GetLastError() << XORW(L"] exiting...\n");
            virtual_free_ex_multiple_and_close_handle(h_proc, p_target_base, p_target_mapping_data, p_shellcode);
            return false;
        }

        const HANDLE h_thread{
            CreateRemoteThread(h_proc, nullptr, 0, (LPTHREAD_START_ROUTINE)p_shellcode, p_target_mapping_data, 0, nullptr)
        };
        if (!h_thread)
        {
            wcerr << XORW(L"CreateRemoteThread() failed: [") << GetLastError() << XORW(L"] exiting...\n");
            virtual_free_ex_multiple_and_close_handle(h_proc, p_target_base, p_target_mapping_data, p_shellcode);
            return false;
        }
        CloseHandle(h_thread);

        wcout << XORW(L"Starting mapping validation...\n");

        while (true)
        {
            DWORD exit_code{0};
            GetExitCodeProcess(h_proc, &exit_code);
            if (exit_code != STILL_ACTIVE)
            {
                wcerr << XORW(L"Process crashed, exit code: dec: ") << exit_code << XORW(L" hex: ") << hex_w_str(exit_code) << '\n';
                return false;
            }

            internal::manual_mapping_data data_check;
            if (!ReadProcessMemory(h_proc, p_target_mapping_data, &data_check, sizeof internal::manual_mapping_data, nullptr))
            {
                wcerr << XORW(L"ReadProcessMemory() for final check failed: [") << GetLastError() << XORW(L"] exiting...\n");
                virtual_free_ex_multiple_and_close_handle(h_proc, p_target_base, p_target_mapping_data, p_shellcode);
                return false;
            }

            if (data_check.dw_check == (DWORD)0x40404040)
            {
                wcerr << XORW(L"Wrong/null function argument for the shellcode, exiting...\n");
                virtual_free_ex_multiple_and_close_handle(h_proc, p_target_base, p_target_mapping_data, p_shellcode);
                return false;
            }

            if (data_check.dw_check == (DWORD)0x40404041 || data_check.dw_check == (DWORD)0x40404042 || data_check.dw_check == (DWORD)0x40404043)
            {
                wcerr << XORW(L"Fail in shellcode: ") << hex_w_str(data_check.dw_check) << '\n';
                virtual_free_ex_multiple_and_close_handle(h_proc, p_target_base, p_target_mapping_data, p_shellcode);
                return false;
            }

            if (data_check.dw_check == (DWORD)0x10101010)
            {
                wcout << XORW(L"Success, shellcode has completed, final check value: ") << hex_w_str(data_check.dw_check) << '\n';
                break;
            }

            wcout << XORW(L"Waiting for shellcode completion, current check: ") << hex_w_str(data_check.dw_check) << '\n';
            Sleep(500);
        }

        // wipe PE headers
        const std::vector<uint8_t> empty_buffer(0x1000, 0);
        WriteProcessMemory(h_proc, p_target_base, empty_buffer.data(), empty_buffer.size(), nullptr);

        for (auto i{0}; i < p_pe_headers->FileHeader.NumberOfSections; i++)
        {
            const IMAGE_SECTION_HEADER section{p_section_headers[i]};
            if (section.Misc.VirtualSize)
            {
                DWORD old_protection{0};
                DWORD new_protection{PAGE_READONLY};

                if ((section.Characteristics & IMAGE_SCN_MEM_WRITE) > 0)
                {
                    new_protection = PAGE_READWRITE;
                }
                else if ((section.Characteristics & IMAGE_SCN_MEM_EXECUTE) > 0)
                {
                    new_protection = PAGE_EXECUTE_READ;
                }
                if (VirtualProtectEx(h_proc, (BYTE*)p_target_base + section.VirtualAddress, section.Misc.VirtualSize, new_protection, &old_protection))
                {
                    std::cout << XOR("Section ") << std::string((char*)section.Name, 8) << XOR(" set as: ") << hex_str(new_protection) << '\n';
                }
                else
                {
                    std::cerr << XOR("FAIL: Section ") << std::string((char*)section.Name, 8) << XOR(" not set as: ") << hex_str(new_protection) << '\n';
                }
            }
        }
        DWORD old{0};
        VirtualProtectEx(h_proc, p_target_base, p_section_headers->VirtualAddress, PAGE_READONLY, &old);

        virtual_free_ex_multiple_and_close_handle(h_proc, p_target_mapping_data, p_shellcode);

        return true;
    }
}
