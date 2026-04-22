#include <cstdio>
#include <chrono>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include <GLFW/glfw3.h>

#include "imgui_src/backends/imgui_impl_glfw.h"
#include "imgui_src/backends/imgui_impl_opengl3.h"
#include "imgui_src/imgui.h"

#include "client/app_ui.h"

namespace {

using FrameClock = std::chrono::steady_clock;

constexpr auto kFocusedFrameBudget = std::chrono::milliseconds(16);
constexpr auto kBackgroundFrameBudget = std::chrono::milliseconds(66);

void RequestWindowAttention(GLFWwindow* window) {
#if defined(GLFW_VERSION_MAJOR) && (GLFW_VERSION_MAJOR > 3 || (GLFW_VERSION_MAJOR == 3 && GLFW_VERSION_MINOR >= 3))
    glfwRequestWindowAttention(window);
#else
    (void)window;
#endif
}

bool FileExists(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    return input.good();
}

std::string FindLinuxFontPath() {
    const std::vector<std::string> candidates{
        "imgui_src/misc/fonts/Cousine-Regular.ttf",
        "imgui_src/misc/fonts/DroidSans.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationMono-Regular.ttf",
        "/usr/share/fonts/liberation/LiberationMono-Regular.ttf",
        "/usr/share/fonts/noto/NotoSansMono-Regular.ttf"
    };
    for (const std::string& candidate : candidates) {
        if (FileExists(candidate)) return candidate;
    }
    return "";
}

float DetectUiScale(GLFWwindow* window) {
    float xscale = 1.0f;
    float yscale = 1.0f;
#if defined(GLFW_VERSION_MAJOR) && (GLFW_VERSION_MAJOR > 3 || (GLFW_VERSION_MAJOR == 3 && GLFW_VERSION_MINOR >= 3))
    glfwGetWindowContentScale(window, &xscale, &yscale);
#else
    (void)window;
#endif
    const float scale = xscale > yscale ? xscale : yscale;
    return scale < 1.0f ? 1.0f : scale;
}

bool IsWindowFocused(GLFWwindow* window) {
    return glfwGetWindowAttrib(window, GLFW_FOCUSED) == GLFW_TRUE;
}

bool IsWindowMinimized(GLFWwindow* window) {
    return glfwGetWindowAttrib(window, GLFW_ICONIFIED) == GLFW_TRUE;
}

void PaceFrame(FrameClock::time_point frameStart, bool lowPowerMode) {
    const auto frameBudget = lowPowerMode ? kBackgroundFrameBudget : kFocusedFrameBudget;
    std::this_thread::sleep_until(frameStart + frameBudget);
}

void ConfigureLinuxUi(GLFWwindow* window) {
    ImGuiIO& io = ImGui::GetIO();
    const float uiScale = DetectUiScale(window);
    ImGui::GetStyle().ScaleAllSizes(uiScale);

    const std::string fontPath = FindLinuxFontPath();
    if (!fontPath.empty()) {
        io.Fonts->AddFontFromFileTTF(fontPath.c_str(), 18.0f * uiScale, nullptr, io.Fonts->GetGlyphRangesDefault());
    }
}

}

int main() {
    if (!glfwInit()) return 1;

    GLFWwindow* window = glfwCreateWindow(960, 620, "~= the river <3>", nullptr, nullptr);
    if (window == nullptr) {
        glfwTerminate();
        return 1;
    }

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::GetIO().IniFilename = nullptr;
    ApplyEliteStyle();
    ConfigureLinuxUi(window);
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    ChatState state;
    ChatClient client(state);
    ClientUiState uiState;
    client.Start();

    double lastTitleUpdate = 0.0;
    while (!glfwWindowShouldClose(window)) {
        const FrameClock::time_point frameStart = FrameClock::now();
        const bool focused = IsWindowFocused(window);
        if (focused) {
            glfwPollEvents();
        } else {
            glfwWaitEventsTimeout(0.05);
        }
        if (glfwWindowShouldClose(window)) break;
        if (IsWindowMinimized(window)) continue;

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        if (state.ConsumeNewMessageFlag()) RequestWindowAttention(window);
        double now = glfwGetTime();
        if (now - lastTitleUpdate > 1.0) {
            lastTitleUpdate = now;
            std::string title = BuildWindowTitle(state);
            glfwSetWindowTitle(window, title.c_str());
        }

        int width = 0;
        int height = 0;
        glfwGetFramebufferSize(window, &width, &height);
        RenderChatUi(client, state, uiState, (float)width, (float)height);

        ImGui::Render();
        glViewport(0, 0, width, height);
        glClearColor(0.01f, 0.01f, 0.02f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
        PaceFrame(frameStart, !focused);
    }

    client.Stop();
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}
