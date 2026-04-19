#pragma once

#include <string>

#include "client/chat_client.h"
#include "client/chat_state.h"

struct ChatUiBuffers {
    char input[512] = "";
    char user[32] = "";
    char pass[32] = "";
    char newUser[32] = "";
    char newPass[32] = "";
    bool autoScroll = true;
    double lastLoginSubmitAt = -1000.0;
    double lastCredentialSubmitAt = -1000.0;
    double lastMessageSubmitAt = -1000.0;
};

void ApplyEliteStyle();
void RenderChatUi(ChatClient& client,
                  ChatState& state,
                  ChatUiBuffers& buffers,
                  float width,
                  float height);
std::string BuildWindowTitle(const ChatState& state);
