#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <GL/GL.h>

#include <cstdio>

#include "imgui_src/backends/imgui_impl_opengl3.h"
#include "imgui_src/backends/imgui_impl_win32.h"
#include "imgui_src/imgui.h"

#include "client/app_ui.h"
#include "common/tor_connection.h"

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam);

namespace {

struct WGLWindowData {
    HDC hdc = nullptr;
};

HGLRC g_hRC = nullptr;
WGLWindowData g_mainWindow;
int g_width = 960;
int g_height = 620;

void RequestWindowAttention(HWND hwnd) {
    FLASHWINFO info{};
    info.cbSize = sizeof(info);
    info.hwnd = hwnd;
    info.dwFlags = FLASHW_TRAY | FLASHW_TIMERNOFG;
    info.uCount = 2;
    FlashWindowEx(&info);
}

bool CreateDeviceWGL(HWND hwnd, WGLWindowData* data) {
    HDC hdc = ::GetDC(hwnd);
    PIXELFORMATDESCRIPTOR pfd{};
    pfd.nSize = sizeof(pfd);
    pfd.nVersion = 1;
    pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
    pfd.iPixelType = PFD_TYPE_RGBA;
    pfd.cColorBits = 32;

    const int pf = ::ChoosePixelFormat(hdc, &pfd);
    if (pf == 0) return false;
    if (::SetPixelFormat(hdc, pf, &pfd) == FALSE) return false;
    ::ReleaseDC(hwnd, hdc);

    data->hdc = ::GetDC(hwnd);
    if (!g_hRC) g_hRC = wglCreateContext(data->hdc);
    return g_hRC != nullptr;
}

void CleanupDeviceWGL(HWND hwnd, WGLWindowData* data) {
    wglMakeCurrent(nullptr, nullptr);
    if (data->hdc) {
        ::ReleaseDC(hwnd, data->hdc);
        data->hdc = nullptr;
    }
}

LRESULT WINAPI WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wParam, lParam))
        return true;

    switch (msg) {
        case WM_SIZE:
            if (wParam != SIZE_MINIMIZED) {
                g_width = LOWORD(lParam);
                g_height = HIWORD(lParam);
            }
            return 0;
        case WM_SYSCOMMAND:
            if ((wParam & 0xfff0) == SC_KEYMENU) return 0;
            break;
        case WM_DESTROY:
            ::PostQuitMessage(0);
            return 0;
    }
    return ::DefWindowProcW(hwnd, msg, wParam, lParam);
}

}

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {
    (void)hInstance; (void)hPrevInstance; (void)lpCmdLine; (void)nShowCmd;
    
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;

    WNDCLASSEXW wc = {
        sizeof(wc), CS_OWNDC, WndProc, 0L, 0L, GetModuleHandle(nullptr),
        nullptr, nullptr, nullptr, nullptr, L"TheRiverClient", nullptr
    };
    ::RegisterClassExW(&wc);
    HWND hwnd = ::CreateWindowW(
        wc.lpszClassName,
        L"~= the river <3>",
        WS_OVERLAPPEDWINDOW,
        100, 100, g_width, g_height,
        nullptr, nullptr, wc.hInstance, nullptr);

    if (!CreateDeviceWGL(hwnd, &g_mainWindow)) {
        CleanupDeviceWGL(hwnd, &g_mainWindow);
        ::DestroyWindow(hwnd);
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        return 1;
    }
    wglMakeCurrent(g_mainWindow.hdc, g_hRC);

    ::ShowWindow(hwnd, SW_SHOWDEFAULT);
    ::UpdateWindow(hwnd);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = nullptr;

    // CARGA DE FUENTE BBS CON SOPORTE PARA TILDES
    ImFontConfig font_cfg;
    font_cfg.FontDataOwnedByAtlas = false;
    // Courier New base para el look BBS.
    io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\cour.ttf", 26.0f, NULL, io.Fonts->GetGlyphRangesDefault());
    
    ApplyEliteStyle();
    ImGui_ImplWin32_InitForOpenGL(hwnd);
    ImGui_ImplOpenGL3_Init();

    // Gestionar el proceso Tor local automáticamente
    EnsureLocalTorIsRunning();

    ChatState state;
    ChatClient client(state);
    ClientUiState uiState;
    client.Start();

    double lastTitleUpdate = 0.0;
    bool done = false;
    while (!done) {
        MSG msg;
        while (::PeekMessage(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
            if (msg.message == WM_QUIT) done = true;
        }
        if (done) break;
        if (::IsIconic(hwnd)) {
            ::Sleep(10);
            continue;
        }

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        if (state.ConsumeNewMessageFlag()) RequestWindowAttention(hwnd);
        double now = ImGui::GetTime();
        if (now - lastTitleUpdate > 1.0) {
            lastTitleUpdate = now;
            std::string title = BuildWindowTitle(state);
            ::SetWindowTextA(hwnd, title.c_str());
        }

        RenderChatUi(client, state, uiState, (float)g_width, (float)g_height);

        ImGui::Render();
        glViewport(0, 0, g_width, g_height);
        glClearColor(0.01f, 0.01f, 0.02f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        ::SwapBuffers(g_mainWindow.hdc);
    }

    client.Stop();
    TerminateLocalTor();
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();

    CleanupDeviceWGL(hwnd, &g_mainWindow);
    if (g_hRC) wglDeleteContext(g_hRC);
    ::DestroyWindow(hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
    WSACleanup();
    return 0;
}
