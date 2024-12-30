#pragma once
#define WIN32_LEAN_AND_MEAN 
#include <Windows.h>
#include "../global.hpp"
#include "../sdk/dumper/offsets.hpp"
#include "../sdk/dumper/client_dll.hpp"
#include "xor.hpp"
#include "logger.hpp"
#include "../sdk/structs.hpp"

namespace cheat::controller
{
    using commons::logger::log;

    class cs2_cheat_controller
    {
    private:
        uintptr_t client_dll_base_{0x0};
        uintptr_t engine_dll_base_{0x0};
        uintptr_t entity_system_{0x0};
        bool ready_{false};

    private:
        [[nodiscard]] static uintptr_t get_client_dll_base();

        [[nodiscard]] static uintptr_t get_engine_dll_base();

        [[nodiscard]] uintptr_t get_entity_system() const;

        [[nodiscard]] const uintptr_t* get_p_network_game_client() const;

    public:
        [[nodiscard]] bool is_ready() const { return ready_; }

        [[nodiscard]] bool is_in_game() const;

        bool init();

        [[nodiscard]] const sdk::CCSPlayerController* get_entity_controller(const int& i) const;

        [[nodiscard]] const sdk::C_CSPlayerPawn* get_entity_pawn(const sdk::CCSPlayerController* p_entity_controller) const;
    };
}
