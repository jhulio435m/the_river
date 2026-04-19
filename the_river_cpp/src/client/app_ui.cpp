#include "client/app_ui.h"

#include <cmath>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "imgui_src/imgui.h"

#include "client/chat_types.h"
#include "client/command_processor.h"
#include "common/shared_config.h"

namespace {

std::string TrimCopy(const char* value) {
    std::string text = value ? value : "";
    const size_t start = text.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    const size_t end = text.find_last_not_of(" \t\r\n");
    return text.substr(start, end - start + 1);
}

ImVec4 StatusColor(ConnState state) {
    switch (state) {
        case ConnState::DISCONNECTED: return ImVec4(0.95f, 0.25f, 0.12f, 1.0f);
        case ConnState::CONNECTING: return ImVec4(0.12f, 0.76f, 0.98f, 1.0f);
        case ConnState::TOR_READY: return ImVec4(0.00f, 0.92f, 0.58f, 1.0f);
        case ConnState::AUTHENTICATING: return ImVec4(0.99f, 0.85f, 0.20f, 1.0f);
        case ConnState::FIRST_LOGIN_REQUIRED: return ImVec4(1.00f, 0.68f, 0.22f, 1.0f);
        case ConnState::UPDATING_CREDENTIALS: return ImVec4(0.96f, 0.72f, 0.28f, 1.0f);
        case ConnState::RECONNECTING: return ImVec4(0.65f, 0.82f, 1.0f, 1.0f);
        case ConnState::AUTHENTICATED: return ImVec4(0.00f, 1.00f, 0.45f, 1.0f);
    }
    return ImVec4(1, 1, 1, 1);
}

const char* StatusLabel(ConnState state) {
    switch (state) {
        case ConnState::DISCONNECTED: return "OFFLINE";
        case ConnState::CONNECTING: return "NEGOCIANDO TOR";
        case ConnState::TOR_READY: return "TOR LISTO";
        case ConnState::AUTHENTICATING: return "AUTENTICANDO";
        case ConnState::FIRST_LOGIN_REQUIRED: return "PRIMER ACCESO";
        case ConnState::UPDATING_CREDENTIALS: return "ACTUALIZANDO";
        case ConnState::RECONNECTING: return "RECONECTANDO";
        case ConnState::AUTHENTICATED: return "SECURE";
    }
    return "UNKNOWN";
}

bool ShouldThrottle(double now, double& lastTick, double intervalSeconds) {
    if (now - lastTick < intervalSeconds) return true;
    lastTick = now;
    return false;
}

void DrawInfoBand(const char* label, const std::string& value, const ImVec4& color) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(color.x * 0.12f, color.y * 0.12f, color.z * 0.12f, 0.95f));
    ImGui::BeginChild(label, ImVec2(0, 58), true);
    ImGui::TextColored(color, "%s", label);
    ImGui::TextWrapped("%s", value.c_str());
    ImGui::EndChild();
    ImGui::PopStyleColor();
}

void DrawErrorBanner(const std::string& error) {
    if (error.empty()) return;
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.24f, 0.03f, 0.02f, 0.96f));
    ImGui::BeginChild("##error_banner", ImVec2(0, 64), true);
    ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.32f, 1.0f), "ULTIMO ERROR");
    ImGui::Separator();
    ImGui::TextWrapped("%s", error.c_str());
    ImGui::EndChild();
    ImGui::PopStyleColor();
}

}

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
        StatusLabel(state.GetConnectionState()),
        state.ActiveUserCount());
    return title;
}

void RenderChatUi(ChatClient& client,
                  ChatState& state,
                  ChatUiBuffers& buffers,
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

    const ConnState connState = state.GetConnectionState();
    const std::string statusDetail = state.StatusDetail();
    const std::string lastError = state.LastError();
    const bool authPending = state.IsAuthActionPending();
    const bool isAuthenticated = state.IsAuthenticated() && connState == ConnState::AUTHENTICATED;

    ImVec4 bbsBlue = ImVec4(0.0f, 0.0f, 0.66f, 1.0f);
    ImVec4 bbsMagenta = ImVec4(1.0f, 0.0f, 1.0f, 1.0f);
    ImVec4 bbsLime = ImVec4(0.0f, 1.0f, 0.0f, 1.0f);
    ImVec4 bbsWhite = ImVec4(1.0f, 1.0f, 1.0f, 1.0f);

    // --- HEADER BBS ---
    ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(0, 0), ImVec2(width, 42), ImColor(bbsBlue));
    ImGui::SetCursorPos(ImVec2(10, 6));
    ImGui::Text("Active Users %d <SECURE UPLINK>", state.ActiveUserCount());

    ImGui::SetCursorPos(ImVec2(width - 320, 2));
    ImGui::TextDisabled("MBmon for MBSE BBS version 0.37.6");
    ImGui::SetCursorPos(ImVec2(width - 320, 18));
    ImGui::TextColored(ImVec4(1, 1, 0, 1), "Copyright (C) 1997-2026");
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.8f, 0, 0, 1));
    ImGui::BeginChild("##Busy", ImVec2(40, 18), false);
    ImGui::Text("Busy");
    ImGui::EndChild();
    ImGui::PopStyleColor();

    // --- BODY ---
    if (!isAuthenticated) {
        // ... (Mantener lógica de carga y login pero adaptada a BBS si es necesario)
        // Por ahora nos centramos en el chat principal solicitado
        const bool isConnecting = connState == ConnState::CONNECTING || 
                                 connState == ConnState::RECONNECTING || 
                                 connState == ConnState::DISCONNECTED;

        if (isConnecting) {
            // ANIMACION "THE RIVER" - MINECRAFT/GLITCH STYLE (FONDO)
            const float t = (float)ImGui::GetTime();
            ImGui::SetCursorPos(ImVec2(0, 0));
            ImGui::BeginChild("##IntroAnim", ImVec2(width, height), false, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoInputs | ImGuiWindowFlags_NoBackground);
            
            // Lluvia de bloques procedimental imitando el video de Minecraft de la película
            for (int y = 0; y < (int)height; y += 24) {
                for (int x = 0; x < (int)width; x += 32) {
                    float noise = std::sin(x * 0.05f + t * 2.5f) * std::cos(y * 0.05f - t * 1.8f);
                    if (noise > 0.35f) {
                        ImGui::SetCursorPos(ImVec2((float)x, (float)y));
                        // Alternancia de rojo/verde estilo glitch cinemático
                        ImVec4 blockCol = (std::sin(t * 12.0f + x) > 0) ? ImVec4(0.8f, 0, 0, 0.35f) : ImVec4(0, 0.8f, 0.4f, 0.35f);
                        ImGui::TextColored(blockCol, "█");
                    }
                }
            }
            ImGui::EndChild();

            ImGui::SetCursorPos(ImVec2(width * 0.5f - 250.0f, height * 0.5f - 70.0f));
            ImGui::BeginChild("##ConnectingPanel", ImVec2(500, 160), true);
            ImGui::TextColored(bbsLime, "UPLINK STATUS: %s", StatusLabel(connState));
            ImGui::Separator();
            ImGui::TextWrapped("%s", statusDetail.c_str());
            ImGui::EndChild();
        } else {
            ImGui::SetCursorPos(ImVec2(width * 0.5f - 220.0f, height * 0.5f - 120.0f));
            ImGui::BeginChild("##AccessPanel", ImVec2(440, 240), true);
            ImGui::TextColored(bbsMagenta, "CHARON SUITE // ACCESS TERMINAL");
            ImGui::Separator();
            ImGui::Spacing();
            ImGui::Text("IDENT:"); ImGui::SameLine();
            ImGui::InputText("##ID", buffers.user, 32);
            ImGui::Text("KEY  :"); ImGui::SameLine();
            ImGui::InputText("##PW", buffers.pass, 32, ImGuiInputTextFlags_Password);
            ImGui::Spacing();
            if (ImGui::Button("ESTABLISH UPLINK", ImVec2(-1, 40))) {
                client.SendLogin(buffers.user, buffers.pass);
            }
            ImGui::EndChild();
        }
    } else {
        // PANEL IZQUIERDO: USUARIOS
        ImGui::SetCursorPos(ImVec2(0, 42));
        ImGui::BeginChild("##Nodes", ImVec2(width * 0.18f, height - 84), false);
        ImGui::Spacing();
        std::vector<std::string> activeUsers = state.SnapshotActiveUsers();
        for (const auto& user : activeUsers) {
            bool isMe = (user == std::string(buffers.user));
            ImGui::TextColored(isMe ? bbsMagenta : bbsLime, " %s", user.c_str());
        }
        ImGui::EndChild();

        // LINEA DIVISORIA (MAS ANCHA Y SIN HUECOS)
        ImGui::GetWindowDrawList()->AddLine(
            ImVec2(width * 0.18f, 42), 
            ImVec2(width * 0.18f, height - 126), 
            ImColor(bbsWhite), 
            2.0f);

        // PANEL DERECHO: CHAT
        ImGui::SetCursorPos(ImVec2(width * 0.18f + 5, 42));
        ImGui::BeginChild("##Feed", ImVec2(width * 0.82f - 5, height - 168), false); // Espacio reducido para el nuevo layout
        std::vector<LogEntry> logs = state.SnapshotLogs();
        for (const auto& entry : logs) {
            if (entry.isSystem) {
                ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1), "%s", entry.text.c_str());
            } else {
                bool isMe = (entry.user == std::string(buffers.user));
                ImColor col = isMe ? ImColor(bbsMagenta) : ImColor(bbsLime);
                ImGui::TextColored(col, "<%s> %s", entry.user.c_str(), entry.text.c_str());
            }
        }
        ImGui::SetScrollHereY(1.0f);
        ImGui::EndChild();

        // --- NUEVA BARRA AZUL SEPARADORA (ENCIMA DEL INPUT) ---
        ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(0, height - 126), ImVec2(width, height - 84), ImColor(bbsBlue));
        
        // --- AREA DE INPUT (ANCHO TOTAL) ---
        ImGui::SetCursorPos(ImVec2(10, height - 74));
        ImGui::TextColored(bbsMagenta, "%s", buffers.user);
        ImGui::SameLine(0, 0);
        ImGui::TextColored(bbsLime, "-->");
        ImGui::SameLine();

        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0, 0, 0, 0));
        ImGui::SetNextItemWidth(-10); // Ocupar el resto del ancho
        if (!ImGui::IsAnyItemActive()) ImGui::SetKeyboardFocusHere(0);
        if (ImGui::InputText("##CMD", buffers.input, 512, ImGuiInputTextFlags_EnterReturnsTrue)) {
            if (buffers.input[0] != '\0') {
                ProcessLocalCommand(client, state, buffers.user, buffers.input);
                std::memset(buffers.input, 0, sizeof(buffers.input));
            }
        }
        ImGui::PopStyleColor();
        ImGui::PopStyleVar();
    }

    // --- FOOTER BBS SINCRONIZADO (ABAJO DEL INPUT) ---
    ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(0, height - 42), ImVec2(width, height), ImColor(bbsBlue));

        // Generar strings de tiempo para el footer
        std::time_t now = std::time(nullptr);
        char hms[16], yr[8], tz[16], dt[32];
        std::strftime(hms, sizeof(hms), "%H:%M:%S", std::localtime(&now));
        std::strftime(yr, sizeof(yr), "%Y", std::localtime(&now));
        std::strftime(tz, sizeof(tz), "TZUTC 0200", std::localtime(&now)); // Hardcoded TZ per spec
        std::strftime(dt, sizeof(dt), "Thu Aug 22", std::localtime(&now)); // Textual date part

        // Centrar el footer
        std::string fullFooter = std::string(hms) + " " + yr + " " + tz + " " + dt + " " + hms + " " + yr + " UTC 0200";
        float footerTextWidth = ImGui::CalcTextSize(fullFooter.c_str()).x;
        ImGui::SetCursorPos(ImVec2((width - footerTextWidth) * 0.5f, height - 32));

        ImVec4 cyanPale = ImVec4(0.6f, 1.0f, 1.0f, 1.0f);
        ImVec4 yellowPale = ImVec4(0.9f, 1.0f, 0.6f, 1.0f);

        ImGui::TextColored(cyanPale, "%s %s %s", hms, yr, tz);
        ImGui::SameLine();
        ImGui::TextColored(yellowPale, " %s ", dt);
        ImGui::SameLine();
        ImGui::TextColored(cyanPale, "%s %s UTC 0200", hms, yr);

        ImGui::End();
        }
