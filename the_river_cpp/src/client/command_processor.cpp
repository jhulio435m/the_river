#include "client/command_processor.h"

#include <cctype>

#include "client/chat_client.h"
#include "client/chat_state.h"
#include "common/security_utils.h"

namespace {

std::string Trim(const std::string& value) {
    const std::size_t start = value.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    const std::size_t end = value.find_last_not_of(" \t\r\n");
    return value.substr(start, end - start + 1);
}

// Splits "<command> <rest...>" keeping the remainder intact (spaces included).
void SplitCommand(const std::string& input, std::string& command, std::string& rest) {
    const std::size_t space = input.find_first_of(" \t");
    if (space == std::string::npos) {
        command = input;
        rest.clear();
        return;
    }
    command = input.substr(0, space);
    rest = Trim(input.substr(space + 1));
}

std::string ToLower(std::string value) {
    for (char& c : value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return value;
}

void SendPrivate(ChatClient& client,
                 ChatState& state,
                 const std::string& currentUser,
                 const std::string& target,
                 const std::string& message) {
    if (!IsValidUsername(target)) {
        state.AddSystemLog("SYSTEM: Invalid target user '" + target + "'.");
        return;
    }
    if (target == currentUser) {
        state.AddSystemLog("SYSTEM: You cannot send a private message to yourself.");
        return;
    }
    if (message.empty()) {
        state.AddSystemLog("SYSTEM: Usage: /msg <user> <message>");
        return;
    }
    if (client.SendPrivateMessage(currentUser, target, message)) {
        state.AddOutgoingPrivateMessage(currentUser, target, message);
        state.SetLastPrivatePeer(target);
    } else {
        state.AddSystemLog("SYSTEM: Could not send the private message.");
    }
}

}  // namespace

void ProcessLocalCommand(ChatClient& client,
                         ChatState& state,
                         const std::string& currentUser,
                         const std::string& rawInput) {
    const std::string input = Trim(rawInput);
    if (input.empty()) return;

    if (input[0] != '/') {
        if (!client.SendChatMessage(currentUser, input))
            state.AddSystemLog("Could not send the message.");
        return;
    }

    std::string command;
    std::string rest;
    SplitCommand(input, command, rest);
    const std::string cmd = ToLower(command);

    if (cmd == "/clear") {
        state.ClearLogs();
        return;
    }

    if (cmd == "/help" || cmd == "/?") {
        state.AddSystemLog("Commands: /clear /help /users /ping /msg <user> <text> /r <text> /fingerprint [user] /trust <user> /logout");
        state.AddSystemLog("  /msg (/pm, /w) sends an end-to-end encrypted private message; /r replies to the last one.");
        state.AddSystemLog("  /fingerprint shows your key fingerprint, or <user>'s; compare it with them over another channel.");
        state.AddSystemLog("  /trust <user> accepts <user>'s changed key (after checking its fingerprint) and sends the messages held for them.");
        state.AddSystemLog("  Up/Down recall sent lines, Tab completes nicknames.");
        state.AddSystemLog("  Admins: /adminhelp lists server commands; other /commands are sent to the server.");
        return;
    }

    if (cmd == "/adminhelp") {
        if (!client.SendChatMessage(currentUser, "/help"))
            state.AddSystemLog("Could not send the message.");
        return;
    }

    if (cmd == "/users" || cmd == "/who") {
        const auto users = state.SnapshotActiveUsers();
        std::string list = "Active nodes (" + std::to_string(users.size()) + "): ";
        for (const auto& user : users) list += user + " ";
        state.AddSystemLog(list);
        return;
    }

    if (cmd == "/ping") {
        if (client.SendPing())
            state.AddSystemLog("PING sent to server.");
        else
            state.AddSystemLog("Could not send PING.");
        return;
    }

    if (cmd == "/msg" || cmd == "/pm" || cmd == "/w") {
        std::string target;
        std::string message;
        SplitCommand(rest, target, message);
        if (target.empty() || message.empty()) {
            state.AddSystemLog("SYSTEM: Usage: /msg <user> <message>");
            return;
        }
        SendPrivate(client, state, currentUser, target, message);
        return;
    }

    if (cmd == "/r" || cmd == "/reply") {
        const std::string target = state.LastPrivatePeer();
        if (target.empty()) {
            state.AddSystemLog("SYSTEM: No private conversation to reply to yet.");
            return;
        }
        if (rest.empty()) {
            state.AddSystemLog("SYSTEM: Usage: /r <message>  (replying to " + target + ")");
            return;
        }
        SendPrivate(client, state, currentUser, target, rest);
        return;
    }

    if (cmd == "/fingerprint" || cmd == "/fp") {
        std::string target;
        std::string extra;
        SplitCommand(rest, target, extra);
        if (!extra.empty()) {
            state.AddSystemLog("SYSTEM: Usage: /fingerprint [user]");
            return;
        }
        client.ShowFingerprint(target);
        return;
    }

    if (cmd == "/trust") {
        std::string target;
        std::string extra;
        SplitCommand(rest, target, extra);
        if (target.empty() || !extra.empty()) {
            state.AddSystemLog("SYSTEM: Usage: /trust <user>");
            return;
        }
        client.TrustPeerKey(target);
        return;
    }

    if (cmd == "/logout" || cmd == "/quit") {
        client.Logout();
        return;
    }

    // Anything else is forwarded to the server, which handles admin commands
    // and answers unknown commands for regular users.
    if (!client.SendChatMessage(currentUser, input))
        state.AddSystemLog("Could not send the message.");
}
