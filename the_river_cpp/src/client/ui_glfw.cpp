#include <cstdio>
#include <string>

#include <GLFW/glfw3.h>

#include "imgui_src/backends/imgui_impl_glfw.h"
#include "imgui_src/backends/imgui_impl_opengl3.h"
#include "imgui_src/imgui.h"

#include "client/app_ui.h"

namespace {

void RequestWindowAttention(GLFWwindow* window) {
#if defined(GLFW_VERSION_MAJOR) && (GLFW_VERSION_MAJOR > 3 || (GLFW_VERSION_MAJOR == 3 && GLFW_VERSION_MINOR >= 3))
    glfwRequestWindowAttention(window);
#else
    (void)window;
#endif
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

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::GetIO().IniFilename = nullptr;
    ApplyEliteStyle();
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    ChatState state;
    ChatClient client(state);
    ChatUiBuffers buffers;
    client.Start();

    double lastTitleUpdate = 0.0;
    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
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
        RenderChatUi(client, state, buffers, (float)width, (float)height);

        ImGui::Render();
        glViewport(0, 0, width, height);
        glClearColor(0.01f, 0.01f, 0.02f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    client.Stop();
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}
