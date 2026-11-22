#pragma once

#include <string>

#include "client/attachment_types.h"

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
