#pragma once

#include <string>

#include "imgui_src/imgui.h"

#include "client/chat_client.h"
#include "client/chat_state.h"
#include "client/client_ui_state.h"

void ApplyEliteStyle();
// Glyph ranges for the UI font: ImGui's default (Basic Latin + Latin-1) plus
// the non-Latin-1 characters the UI draws itself (U+2588 FULL BLOCK in the
// connection screen background) and common typography in chat text. Pass it
// to every AddFontFromFileTTF call; without it those characters render as '?'.
const ImWchar* UiGlyphRanges();
void RenderChatUi(ChatClient& client,
                  ChatState& state,
                  ClientUiState& uiState,
                  float width,
                  float height);
std::string BuildWindowTitle(const ChatState& state);
