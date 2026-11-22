#pragma once

#include <string>
#include <utility>

#include "client/attachment_types.h"

// A status/error text the client shows on the connection, login and
// first-access screens, in both UI languages. ChatClient (network thread) sets
// it; the UI thread picks the language of its own toggle (ClientUiState). A
// single string (e.g. a notice relayed from the server) is used for both.
struct UiText {
    std::string en;
    std::string es;

    UiText() = default;
    UiText(const char* both) : en(both ? both : ""), es(en) {}
    UiText(const std::string& both) : en(both), es(both) {}
    UiText(std::string english, std::string spanish) : en(std::move(english)), es(std::move(spanish)) {}

    bool empty() const { return en.empty() && es.empty(); }
    void clear() {
        en.clear();
        es.clear();
    }
    const std::string& For(bool spanish) const { return spanish ? es : en; }
};

enum class ConnState {
    DISCONNECTED,
    CONNECTING,
    TOR_READY,
    AUTHENTICATING,
    FIRST_LOGIN_REQUIRED,
    UPDATING_CREDENTIALS,
    RECONNECTING,
    AUTHENTICATED
};

struct LogEntry {
    std::string time;
    std::string user;
    std::string text;
    bool isSystem = false;
    bool isPM = false;
    bool isAttachment = false;
    AttachmentPayload attachment;
    // Server timestamp of MSG/HIST/PM2 entries (0 for local lines).
    long long unixTs = 0;
    // Entry came from the HISTORY block (never raises a new-message notification).
    bool isHistory = false;
};
