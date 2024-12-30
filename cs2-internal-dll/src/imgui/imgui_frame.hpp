#pragma once
#include <d3d11.h>
#include <xor.hpp>
#include "lib/imgui.h"
#include "lib/backends/imgui_impl_win32.h"
#include "lib/backends/imgui_impl_dx11.h"

namespace cheat::imgui
{
    namespace g
    {
        static inline ID3D11Device* g_pd3d_device{nullptr};
        static inline ID3D11DeviceContext* g_pd3d_device_context{nullptr};
        static inline IDXGISwapChain* g_p_swap_chain{nullptr};
        static inline bool g_swap_chain_occluded{false};
        static inline UINT g_resize_width{0};
        static inline UINT g_resize_height{0};
        static inline ID3D11RenderTargetView* g_main_render_target_view{nullptr};

        static inline WNDCLASSEXW overlay_wnd_class;
        static inline HWND h_overlay;
        constexpr auto overlay_window_name{XORW(L"zzxzz")};
        constexpr auto font_size{20.0f};
    }

    LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);
    bool create_device_d_3d(HWND hWnd);
    void cleanup_device_d_3d();
    void create_render_target();
    void cleanup_render_target();

    inline void init()
    {
        g::overlay_wnd_class = WNDCLASSEXW{
            sizeof(g::overlay_wnd_class),
            CS_HREDRAW | CS_VREDRAW,
            WndProc,
            0L,
            0L,
            GetModuleHandle(nullptr),
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            XORW(L"win"),
            nullptr
        };

        RegisterClassExW(&g::overlay_wnd_class);

        g::h_overlay = CreateWindowExW(WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TOOLWINDOW | WS_EX_TRANSPARENT,
                                       g::overlay_wnd_class.lpszClassName,
                                       g::overlay_window_name,
                                       WS_POPUP,
                                       0,
                                       0,
                                       ::g::screen_width,
                                       ::g::screen_height,
                                       nullptr,
                                       nullptr,
                                       g::overlay_wnd_class.hInstance,
                                       nullptr);

        SetLayeredWindowAttributes(g::h_overlay, RGB(0, 0, 0), 255, LWA_ALPHA | LWA_COLORKEY);

        // Initialize Direct3D
        if (!create_device_d_3d(g::h_overlay))
        {
            cleanup_device_d_3d();
            UnregisterClassW(g::overlay_wnd_class.lpszClassName, g::overlay_wnd_class.hInstance);
            return;
        }

        // Show the window
        ShowWindow(g::h_overlay, SW_SHOWDEFAULT);
        UpdateWindow(g::h_overlay);

        // Setup Dear ImGui context
        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImGuiIO& io{ImGui::GetIO()};
        (void)io;
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

        ImGui::StyleColorsDark();

        ImGui_ImplWin32_Init(g::h_overlay);
        ImGui_ImplDX11_Init(g::g_pd3d_device, g::g_pd3d_device_context);
    }

    namespace frame
    {
        enum frame_state
        {
            frame_quit,
            frame_success,
            frame_skip
        };

        inline void cleanup()
        {
            ImGui_ImplDX11_Shutdown();
            ImGui_ImplWin32_Shutdown();
            ImGui::DestroyContext();

            cleanup_device_d_3d();
            DestroyWindow(g::h_overlay);
            UnregisterClassW(g::overlay_wnd_class.lpszClassName, g::overlay_wnd_class.hInstance);
        }

        inline frame_state start_frame()
        {
            // Poll and handle messages (inputs, window resize, etc.)
            // See the WndProc() function below for our to dispatch events to the Win32 backend.
            MSG msg;
            while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE))
            {
                TranslateMessage(&msg);
                ::DispatchMessage(&msg);
                if (msg.message == WM_QUIT)
                    return frame_quit;
            }

            // Handle window screen locked
            if (g::g_swap_chain_occluded && g::g_p_swap_chain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED)
            {
                Sleep(10);
                return frame_skip;
            }
            g::g_swap_chain_occluded = false;

            // Start the Dear ImGui frame
            ImGui_ImplDX11_NewFrame();
            ImGui_ImplWin32_NewFrame();
            ImGui::NewFrame();

            return frame_success;
        }

        inline void render()
        {
            ImGui::Render();
            constexpr float transparent[4]{0, 0, 0, 0};
            g::g_pd3d_device_context->OMSetRenderTargets(1, &g::g_main_render_target_view, nullptr);
            g::g_pd3d_device_context->ClearRenderTargetView(g::g_main_render_target_view, transparent);
            ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

            // Present
            HRESULT hr{g::g_p_swap_chain->Present(1, 0)}; // Present with vsync
            //HRESULT hr = g_pSwapChain->Present(0, 0); // Present without vsync
            g::g_swap_chain_occluded = (hr == DXGI_STATUS_OCCLUDED);
        }
    }

#pragma region imgui_helpers
    inline bool create_device_d_3d(HWND hWnd)
    {
        // Setup swap chain
        DXGI_SWAP_CHAIN_DESC sd;
        ZeroMemory(&sd, sizeof(sd));
        sd.BufferCount = 2;
        sd.BufferDesc.Width = 0;
        sd.BufferDesc.Height = 0;
        sd.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        sd.BufferDesc.RefreshRate.Numerator = 60;
        sd.BufferDesc.RefreshRate.Denominator = 1;
        sd.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
        sd.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        sd.OutputWindow = hWnd;
        sd.SampleDesc.Count = 1;
        sd.SampleDesc.Quality = 0;
        sd.Windowed = TRUE;
        sd.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

        UINT createDeviceFlags = 0;
        //createDeviceFlags |= D3D11_CREATE_DEVICE_DEBUG;
        D3D_FEATURE_LEVEL feature_level;
        constexpr D3D_FEATURE_LEVEL featureLevelArray[2] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0,};
        HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g::g_p_swap_chain, &g::g_pd3d_device, &feature_level, &g::g_pd3d_device_context);
        if (res == DXGI_ERROR_UNSUPPORTED) // Try high-performance WARP software driver if hardware is not available.
            res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, createDeviceFlags, featureLevelArray, 2, D3D11_SDK_VERSION, &sd, &g::g_p_swap_chain, &g::g_pd3d_device, &feature_level, &g::g_pd3d_device_context);
        if (res != S_OK)
            return false;

        create_render_target();
        return true;
    }

    inline void cleanup_device_d_3d()
    {
        cleanup_render_target();
        if (g::g_p_swap_chain)
        {
            g::g_p_swap_chain->Release();
            g::g_p_swap_chain = nullptr;
        }
        if (g::g_pd3d_device_context)
        {
            g::g_pd3d_device_context->Release();
            g::g_pd3d_device_context = nullptr;
        }
        if (g::g_pd3d_device)
        {
            g::g_pd3d_device->Release();
            g::g_pd3d_device = nullptr;
        }
    }

    inline void create_render_target()
    {
        ID3D11Texture2D* p_back_buffer;
        g::g_p_swap_chain->GetBuffer(0, IID_PPV_ARGS(&p_back_buffer));
        g::g_pd3d_device->CreateRenderTargetView(p_back_buffer, nullptr, &g::g_main_render_target_view);
        p_back_buffer->Release();
    }

    inline void cleanup_render_target()
    {
        if (g::g_main_render_target_view)
        {
            g::g_main_render_target_view->Release();
            g::g_main_render_target_view = nullptr;
        }
    }

    // Forward declare message handler from imgui_impl_win32.cpp
    extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

    // Win32 message handler
    // You can read the io.WantCaptureMouse, io.WantCaptureKeyboard flags to tell if dear imgui wants to use your inputs.
    // - When io.WantCaptureMouse is true, do not dispatch mouse input data to your main application, or clear/overwrite your copy of the mouse data.
    // - When io.WantCaptureKeyboard is true, do not dispatch keyboard input data to your main application, or clear/overwrite your copy of the keyboard data.
    // Generally you may always pass all inputs to dear imgui, and hide them from your application based on those two flags.
    inline LRESULT WINAPI WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
    {
        if (ImGui_ImplWin32_WndProcHandler(hWnd, msg, wParam, lParam))
            return true;

        switch (msg)
        {
        case WM_SIZE:
            if (wParam == SIZE_MINIMIZED)
                return 0;
            g::g_resize_width = (UINT)LOWORD(lParam); // Queue resize
            g::g_resize_height = (UINT)HIWORD(lParam);
            return 0;
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU) // Disable ALT application menu
                return 0;
            break;
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
        }
        return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
#pragma endregion imgui_helpers
}
