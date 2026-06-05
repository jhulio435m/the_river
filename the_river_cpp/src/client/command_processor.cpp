#include "client/command_processor.h"

#include "client/chat_client.h"
#include "client/chat_state.h"

void ProcessLocalCommand(ChatClient& client,
                         ChatState& state,
                         const std::string& currentUser,
                         const std::string& input) {
    if (input == "/clear") {
        state.ClearLogs();
        return;
    }

    if (input == "/help") {
        state.AddSystemLog("Commands: /clear /help /users /ping");
        return;
    }

    if (input == "/users") {
        std::string list = "Active nodes: ";
        for (const auto& user : state.SnapshotActiveUsers()) list += user + " ";
        state.AddSystemLog(list);
        return;
    }

    if (input == "/ping") {
        if (client.SendPing())
            state.AddSystemLog("PING sent to server.");
        else
            state.AddSystemLog("Could not send PING.");
        return;
    }

    if (!input.empty()) {
        if (!client.SendChatMessage(currentUser, input))
            state.AddSystemLog("Could not send the message.");
    }
}
