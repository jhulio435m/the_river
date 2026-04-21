#include "client/app_ui.h"

#include <cstdio>
#include <string>

#include "imgui_src/imgui.h"

#include "client/ui_sections.h"

void ApplyEliteStyle() {
    ImGuiStyle& s = ImGui::GetStyle();
    
    // BBS Style: Hard edges
    s.WindowRounding = 0.0f;
    s.FrameRounding = 0.0f;
    s.ScrollbarRounding = 0.0f;
    s.ChildRounding = 0.0f;
    s.ItemSpacing = ImVec2(8, 2);

    /* OLD CINEMATIC STYLE - Commented out
    s.Colors[ImGuiCol_WindowBg] = ImVec4(0.004f, 0.006f, 0.004f, 1.0f);
    s.Colors[ImGuiCol_Border] = ImVec4(0.0f, 1.0f, 0.4f, 0.35f);
    s.Colors[ImGuiCol_Text] = ImVec4(0.0f, 1.0f, 0.4f, 1.0f);
    */

    // BBS COLORS (Retro TTY)
    ImVec4 bbsBlue = ImVec4(0.0f, 0.0f, 0.66f, 1.0f);
    ImVec4 bbsMagenta = ImVec4(1.0f, 0.0f, 1.0f, 1.0f);
    ImVec4 bbsLime = ImVec4(0.0f, 1.0f, 0.0f, 1.0f);
    ImVec4 bbsWhite = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);

    s.Colors[ImGuiCol_WindowBg] = ImVec4(0, 0, 0, 1);
    s.Colors[ImGuiCol_Border] = bbsWhite;
    s.Colors[ImGuiCol_Text] = bbsWhite;
    s.Colors[ImGuiCol_Button] = bbsBlue;
    s.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.0f, 0.0f, 0.8f, 1.0f);
    s.Colors[ImGuiCol_ButtonActive] = bbsBlue;
    s.Colors[ImGuiCol_FrameBg] = ImVec4(0, 0, 0, 1);
    s.Colors[ImGuiCol_ChildBg] = ImVec4(0, 0, 0, 1);
    s.Colors[ImGuiCol_Separator] = bbsWhite;
    s.Colors[ImGuiCol_Header] = bbsBlue;
    s.Colors[ImGuiCol_HeaderHovered] = ImVec4(0, 0, 0.8f, 1);
    s.Colors[ImGuiCol_TitleBg] = bbsBlue;
    s.Colors[ImGuiCol_TitleBgActive] = bbsBlue;
}

std::string BuildWindowTitle(const ChatState& state) {
    char title[256];
    std::snprintf(
        title,
        sizeof(title),
        "~= the river <3>  [%s]  [Nodes: %d]",
        UiStatusLabel(state.GetConnectionState()),
        state.ActiveUserCount());
    return title;
}

void RenderChatUi(ChatClient& client,
                  ChatState& state,
                  ClientUiState& uiState,
                  float width,
                  float height) {
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(ImVec2(width, height));
    ImGui::Begin(
        "##MAIN",
        nullptr,
        ImGuiWindowFlags_NoTitleBar |
            ImGuiWindowFlags_NoResize |
            ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoScrollbar |
            ImGuiWindowFlags_NoScrollWithMouse |
            ImGuiWindowFlags_NoBringToFrontOnFocus);

    const UiPalette palette{
        ImVec4(0.0f, 0.0f, 0.66f, 1.0f),
        ImVec4(1.0f, 0.0f, 1.0f, 1.0f),
        ImVec4(0.0f, 1.0f, 0.0f, 1.0f),
        ImVec4(1.0f, 1.0f, 1.0f, 1.0f)
    };

    RenderHeaderBar(state, width, palette);
    if (state.IsAuthenticated() && state.GetConnectionState() == ConnState::AUTHENTICATED)
        RenderAuthenticatedUi(client, state, uiState, width, height, palette);
    else
        RenderUnauthenticatedUi(client, state, uiState, width, height, palette);
    RenderFooterBar(width, height);

    ImGui::End();
}
