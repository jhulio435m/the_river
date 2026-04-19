#pragma once

#include <string>

class ChatClient;
class ChatState;

void ProcessLocalCommand(ChatClient& client,
                         ChatState& state,
                         const std::string& currentUser,
                         const std::string& input);
