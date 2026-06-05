#pragma once

#include "imgui_src/imgui.h"

#include "client/chat_types.h"
#include "client/client_ui_state.h"

class ChatClient;
class ChatState;

struct UiPalette {
    ImVec4 bbsBlue;
    ImVec4 bbsMagenta;
    ImVec4 bbsLime;
    ImVec4 bbsWhite;
};

const char* UiStatusLabel(ConnState state);
ImVec4 UiStatusColor(ConnState state);

void RenderHeaderBar(ChatState& state, ClientUiState& uiState, float width, const UiPalette& palette);
void RenderUnauthenticatedUi(ChatClient& client,
                             ChatState& state,
                             ClientUiState& uiState,
                             float width,
                             float height,
                             const UiPalette& palette);
void RenderAuthenticatedUi(ChatClient& client,
                           ChatState& state,
                           ClientUiState& uiState,
                           float width,
                           float height,
                           const UiPalette& palette);
void RenderFooterBar(float width, float height);
