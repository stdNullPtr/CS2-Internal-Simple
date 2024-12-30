#pragma once
#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#include "../global.hpp"
#include "../sdk/dumper/offsets.hpp"
#include "xor.hpp"
#include "logger.hpp"

namespace cheat
{
    using commons::logger::log;

    class cs2_cheat_controller
    {
        uintptr_t client_dll_base_{0x0};
        uintptr_t engine_dll_base_{0x0};
        bool ready_{false};

    private:
        [[nodiscard]] static uintptr_t get_client_dll_base()
        {
            const auto result{reinterpret_cast<uintptr_t>(GetModuleHandle(g::client_dll_module_name.c_str()))};
            if (!result)
            {
                log(XORW(L"[-] client dll base is 0x0!\n"));
            }
            return result;
        }

        [[nodiscard]] static uintptr_t get_engine_dll_base()
        {
            const auto result{reinterpret_cast<uintptr_t>(GetModuleHandle(g::engine_dll_module_name.c_str()))};
            if (!result)
            {
                log(XORW(L"[-] engine dll base is 0x0!\n"));
            }
            return result;
        }

        [[nodiscard]] uintptr_t* get_p_network_game_client() const
        {
            if (!engine_dll_base_)
            {
                log(XORW(L"[-] Can't get network game client because engine dll is 0x0!\n"));
            }

            auto* const result{(uintptr_t*)(engine_dll_base_ + cs2_dumper::offsets::engine2_dll::dwNetworkGameClient)};
            if (!result)
            {
                log(XORW(L"[-] network game client is null!\n"));
            }
            return result;
        }

    public:
        [[nodiscard]] bool is_ready() const
        {
            return ready_;
        }

        [[nodiscard]] bool is_in_game() const
        {
            const auto* const p_network_game_client{ get_p_network_game_client() };
            if (!p_network_game_client)
            {
                log(XORW(L"[-] Can't check is_in_game - network game client is null!\n"));
                return false;
            }

            const auto is_background{*(bool*)(*p_network_game_client + cs2_dumper::offsets::engine2_dll::dwNetworkGameClient_isBackgroundMap)};
            const auto sign_on_state{*(int*)(*p_network_game_client + cs2_dumper::offsets::engine2_dll::dwNetworkGameClient_signOnState)};
            return !is_background && sign_on_state >= 6;
        }

        bool init()
        {
            auto result{true};

            result &= (client_dll_base_ = get_client_dll_base()) != 0x0;
            result &= (engine_dll_base_ = get_engine_dll_base()) != 0x0;

            return ready_ = result;
        }
    };
}
