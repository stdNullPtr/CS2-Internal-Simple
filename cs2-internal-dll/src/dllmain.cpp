#define WIN32_LEAN_AND_MEAN  
#include <windows.h>
#ifndef NDEBUG
#include "console.hpp"
#endif
#include "xor.hpp"
#include <thread>
#include "global.hpp"
#include "logger.hpp"
#include "keyboard.hpp"
#include "controller/cs2_cheat_controller.hpp"
#include "imgui/imgui_frame.hpp"

static_assert(sizeof(uintptr_t) == 8, "Expected 64-bit environment");

using commons::logger::log;
using std::this_thread::sleep_for;
using namespace std::chrono_literals;
using namespace g::toggles;

namespace
{
    void set_click_through(const bool& enabled)
    {
        if (enabled)
        {
            SetWindowLong(cheat::imgui::g::h_overlay, GWL_EXSTYLE, GetWindowLong(cheat::imgui::g::h_overlay, GWL_EXSTYLE) | WS_EX_TRANSPARENT);
        }
        else
        {
            SetWindowLong(cheat::imgui::g::h_overlay, GWL_EXSTYLE, GetWindowLong(cheat::imgui::g::h_overlay, GWL_EXSTYLE) & ~WS_EX_TRANSPARENT);
        }
    }

    DWORD WINAPI main_routine(LPVOID h_module)
    {
#ifndef NDEBUG
        commons::console::init_console();
        commons::console::set_cursor_visibility(false);
#endif

        cheat::controller::cs2_cheat_controller cheat;

        log(XORW(L"[+] Base address: '0x%llX' press END to exit\n"), h_module);

        while (!commons::keyboard::was_key_pressed(VK_END))
        {
#ifndef NDEBUG
            commons::console::clear_console({0, 1});
#endif

            if (!cheat.is_ready())
            {
                log(XORW(L"[~] Cheat is not initialized, will attempt to initialize."));
                cheat.init();
                sleep_for(1s);
                continue;
            }

            if (!cheat.is_in_game())
            {
                log(XORW(L"[~] Waiting for you to join game...\n"));
                g::toggles::reset();
                sleep_for(1s);
                continue;
            }

            if (GetAsyncKeyState(VK_F1) & 0x1)
            {
                is_paused = !is_paused;
            }

            if (GetAsyncKeyState(VK_F2) & 0x1)
            {
                esp_hack = !esp_hack;
            }

            if (GetAsyncKeyState(VK_F3) & 0x1)
            {
                aim_hack = !aim_hack;
            }

            if (GetAsyncKeyState(VK_F4) & 0x1 && aim_hack)
            {
                aim_assist = !aim_assist;
            }

            if (GetAsyncKeyState(VK_INSERT) & 0x1)
            {
                show_menu = !show_menu;
            }

            log(XORW(L"\n[F1] Pause\n\n"));

            cheat::imgui::init();

            const auto frame_state{ cheat::imgui::frame::start_frame() };
            if (frame_state == cheat::imgui::frame::frame_quit)
            {
                break;
            }

            if (frame_state == cheat::imgui::frame::frame_skip)
            {
                continue;
            }

            for (int i{1}; i < 64; i++)
            {
                const cheat::sdk::CCSPlayerController* const controller{cheat.get_entity_controller(i)};
                if (!controller)
                {
                    continue;
                }

                const cheat::sdk::C_CSPlayerPawn* const pawn{cheat.get_entity_pawn(controller)};
                if (!pawn)
                {
                    continue;
                }

                log(XOR("Name: %s\n"), controller->m_sSanitizedPlayerName);
                log(XORW(L"HP: %d\n"), pawn->m_iHealth);

                if (show_menu)
                {
                    set_click_through(false);
                    ImGui::PushStyleColor(ImGuiCol_WindowBg, IM_COL32(30, 30, 30, 230));
                    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(10, 10));
                    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.0f);

                    ImGui::Begin(XOR("XD"), &show_menu, ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_AlwaysAutoResize);

                    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(0, 128, 255, 255));
                    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(5, 2));
                    ImGui::SeparatorText(XOR("Toggles"));
                    ImGui::PopStyleVar();
                    ImGui::PopStyleColor();

                    ImGui::PushStyleColor(ImGuiCol_FrameBg, IM_COL32(50, 50, 50, 255));
                    ImGui::PushStyleColor(ImGuiCol_FrameBgHovered, IM_COL32(70, 70, 70, 255));
                    ImGui::PushStyleColor(ImGuiCol_CheckMark, IM_COL32(0, 128, 255, 255));

                    ImGui::Checkbox(XOR("[F1] Pause "), &is_paused);
                    ImGui::SameLine();

                    if (is_paused)
                    {
                        ImGui::BeginDisabled();
                    }

                    ImGui::Checkbox(XOR("[F2] ESP "), &esp_hack);
                    ImGui::SameLine();

                    ImGui::Checkbox(XOR("[F3] AIM (hold middle mouse)"), &aim_hack);
                    ImGui::SameLine();

                    if (!aim_hack)
                    {
                        ImGui::BeginDisabled();
                    }
                    ImGui::Checkbox(XOR("[F4] AIM assist (just shoot) "), &aim_assist);
                    ImGui::SameLine();

                    ImGui::Checkbox(XOR("Through walls "), &aim_through_walls);
                    ImGui::SameLine();
                    if (!aim_hack)
                    {
                        ImGui::EndDisabled();
                    }

                    ImGui::Checkbox(XOR("Radar (Unsafe) "), &radar_hack);
                    ImGui::SameLine();

                    ImGui::Checkbox(XOR("Glow (Unsafe) "), &glow_hack);
                    ImGui::SameLine();

                    ImGui::Checkbox(XOR("No flash (Unsafe)"), &no_flash_hack);
                    ImGui::SameLine();

                    if (is_paused)
                    {
                        ImGui::EndDisabled();
                    }
                    ImGui::PopStyleColor(3);

                    ImGui::SeparatorText(XOR("Common"));
                    ImGui::Text(XOR("[INS] Minimize "));
                    ImGui::SameLine();

                    ImGui::Text(XOR("[END] Exit "));
                    ImGui::SameLine();

                    ImGui::Text(XOR("[Open Game console] Free mouse and allow interaction"));

                    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(0, 128, 255, 255));
                    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(5, 2));
                    ImGui::SeparatorText(XOR("ESP Colors"));
                    ImGui::PopStyleVar();
                    ImGui::PopStyleColor();

                    ImGui::ColorEdit3(XOR("Box"), reinterpret_cast<float*>(&g::esp_color));
                    ImGui::ColorEdit3(XOR("Box when enemy visible"), reinterpret_cast<float*>(&g::esp_color_enemy_visible));
                    ImGui::ColorEdit3(XOR("Health"), reinterpret_cast<float*>(&g::esp_health_color));
                    ImGui::ColorEdit3(XOR("Text"), reinterpret_cast<float*>(&g::text_color));
                    ImGui::ColorEdit3(XOR("Carrying AWP text"), reinterpret_cast<float*>(&g::weapon_awp_text_color));
                    ImGui::ColorEdit3(XOR("Carrying knife text"), reinterpret_cast<float*>(&g::weapon_knife_text_color));
                    ImGui::ColorEdit3(XOR("Extra info"), reinterpret_cast<float*>(&g::additional_screen_info_text_color));

                    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(0, 128, 255, 255));
                    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(5, 2));
                    ImGui::SeparatorText(XOR("ESP Config"));
                    ImGui::PopStyleVar();
                    ImGui::PopStyleColor();

                    ImGui::SliderFloat(XOR("Thickness"), &g::esp_box_thickness, 1.0f, 3.0f);
                    ImGui::SliderFloat(XOR("Aim FOV"), &g::aim_fov, 5.0f, 300.0f);
                    ImGui::SliderInt(XOR("Extra info X"), &g::additional_screen_info_position_x, 50, 300);
                    ImGui::SliderInt(XOR("Extra info Y"), &g::additional_screen_info_position_y, 0, 700);

                    ImGui::End();

                    ImGui::PopStyleVar(2);
                    ImGui::PopStyleColor();
                }
                else
                {
                    set_click_through(true);
                }


            }

            cheat::imgui::frame::render();

            sleep_for(10ms);
        }

        cheat::imgui::frame::cleanup();

#ifndef NDEBUG
        commons::console::destroy_console();
#endif

        // *Comment is for manual mapping*
        // TODO: this is potentially bad since we definitely did not manually map in a perfect way like the Windows loader does, so we can't rely on it to unload
        // It definitely does not work currently and the bytes are left in memory.
        FreeLibraryAndExitThread(static_cast<HMODULE>(h_module), 0);
    }
}

// Important: DO NOT CHANGE SIGNATURE/NAMING CONVENTION of this function
// ReSharper disable once CppInconsistentNaming
BOOL WINAPI DllMain(HINSTANCE h_module, DWORD fdw_reason, [[maybe_unused]] LPVOID lp_reserved) // NOLINT(misc-use-internal-linkage)
{
    if (fdw_reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(h_module);
        CloseHandle(CreateThread(nullptr, NULL, main_routine, h_module, NULL, nullptr));
    }

    return TRUE;
}
