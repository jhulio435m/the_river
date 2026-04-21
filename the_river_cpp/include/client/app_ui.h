#pragma once

#include <string>

#include "client/chat_client.h"
#include "client/chat_state.h"
#include "client/client_ui_state.h"

void ApplyEliteStyle();
void RenderChatUi(ChatClient& client,
                  ChatState& state,
                  ClientUiState& uiState,
                  float width,
                  float height);
std::string BuildWindowTitle(const ChatState& state);
