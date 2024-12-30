#include "cs2_cheat_controller.hpp"

namespace cheat::controller
{
    uintptr_t cs2_cheat_controller::get_client_dll_base()
    {
        const auto result{reinterpret_cast<uintptr_t>(GetModuleHandle(g::client_dll_module_name.c_str()))};
        if (!result)
        {
            log(XORW(L"[-] client dll base is 0x0!\n"));
        }
        return result;
    }

    uintptr_t cs2_cheat_controller::get_engine_dll_base()
    {
        const auto result{reinterpret_cast<uintptr_t>(GetModuleHandle(g::engine_dll_module_name.c_str()))};
        if (!result)
        {
            log(XORW(L"[-] engine dll base is 0x0!\n"));
        }
        return result;
    }

    uintptr_t cs2_cheat_controller::get_entity_system() const
    {
        if (!client_dll_base_)
        {
            log(XORW(L"[-] Can't get entity_system because client dll is 0x0!\n"));
        }

        const auto result{*(uintptr_t*)(client_dll_base_ + cs2_dumper::offsets::client_dll::dwEntityList)};
        if (!result)
        {
            log(XORW(L"[-] entity system is null!\n"));
        }
        return result;
    }

    const uintptr_t* cs2_cheat_controller::get_p_network_game_client() const
    {
        if (!engine_dll_base_)
        {
            log(XORW(L"[-] Can't get network game client because engine dll is 0x0!\n"));
        }

        const auto* const result{(uintptr_t*)(engine_dll_base_ + cs2_dumper::offsets::engine2_dll::dwNetworkGameClient)};
        if (!result)
        {
            log(XORW(L"[-] network game client is null!\n"));
        }
        return result;
    }

    bool cs2_cheat_controller::is_in_game() const
    {
        const auto* const p_network_game_client{get_p_network_game_client()};
        if (!p_network_game_client)
        {
            log(XORW(L"[-] Can't check is_in_game - network game client is null!\n"));
            return false;
        }

        const auto is_background{*(bool*)(*p_network_game_client + cs2_dumper::offsets::engine2_dll::dwNetworkGameClient_isBackgroundMap)};
        const auto sign_on_state{*(int*)(*p_network_game_client + cs2_dumper::offsets::engine2_dll::dwNetworkGameClient_signOnState)};
        return !is_background && sign_on_state >= 6;
    }

    bool cs2_cheat_controller::init()
    {
        auto result{true};

        result &= (client_dll_base_ = get_client_dll_base()) != 0x0;
        result &= (engine_dll_base_ = get_engine_dll_base()) != 0x0;

        if (client_dll_base_)
        {
            result &= (entity_system_ = get_entity_system()) != 0x0;
        }

        return ready_ = result;
    }

    const sdk::CCSPlayerController* cs2_cheat_controller::get_entity_controller(const int& i) const
    {
        const auto* const p_list_entity{(uintptr_t*)(entity_system_ + ((8 * (i & 0x7FFF) >> 9) + 16))};
        if (!p_list_entity || !*p_list_entity)
        {
            log(XORW(L"[-] list_entity is invalid!\n"));
            return nullptr;
        }

        const auto* const p_entity_controller{(uintptr_t*)(*p_list_entity + 0x78ll * (i & 0x1FF))};
        if (!p_entity_controller || !*p_entity_controller)
        {
            return nullptr;
        }

        return (sdk::CCSPlayerController*)*p_entity_controller;
    }

    const sdk::C_CSPlayerPawn* cs2_cheat_controller::get_entity_pawn(const sdk::CCSPlayerController* const p_entity_controller) const
    {
        const auto* const list_entity{(uintptr_t*)(entity_system_ + (0x8 * ((p_entity_controller->m_hPlayerPawn & 0x7FFF) >> 9) + 0x10))};
        if (!list_entity || !*list_entity)
        {
            return nullptr;
        }

        const auto* const entity_pawn{(uintptr_t*)(*list_entity + 0x78 * (p_entity_controller->m_hPlayerPawn & 0x1FF))};
        if (!entity_pawn || !*entity_pawn)
        {
            log(XORW(L"Cant grab player pawn, maybe the player disconnected?\n"));
            return nullptr;
        }

        return (sdk::C_CSPlayerPawn*)*entity_pawn;
    }
}
