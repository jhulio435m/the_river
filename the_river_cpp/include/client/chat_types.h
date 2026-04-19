#pragma once

#include <string>

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
};
