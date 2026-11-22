#pragma once

// Small persisted UI preferences (key=value lines in river_client.cfg, stored in
// the working directory next to the client's other runtime files). Header-only so
// it needs no build-system changes. Unknown keys, malformed lines and a missing or
// unreadable file are ignored: defaults from ClientUiState are kept.

#include <cstddef>
#include <cstdio>
#include <fstream>
#include <string>

#include "client/client_ui_state.h"

namespace client_settings {

constexpr const char* kSettingsFileName = "river_client.cfg";
constexpr std::size_t kMaxSettingsLineLength = 256;
constexpr int kMaxSettingsLines = 64;

inline std::string TrimSettingsToken(const std::string& value) {
    const char* ws = " \t\r\n";
    const std::size_t begin = value.find_first_not_of(ws);
    if (begin == std::string::npos) return "";
    const std::size_t end = value.find_last_not_of(ws);
    return value.substr(begin, end - begin + 1);
}

inline bool ParseSettingsBool(const std::string& value, bool& out) {
    if (value == "1" || value == "true") {
        out = true;
        return true;
    }
    if (value == "0" || value == "false") {
        out = false;
        return true;
    }
    return false;
}

inline void LoadClientSettings(ClientUiState& uiState, const char* path = kSettingsFileName) {
    std::ifstream in(path);
    if (!in.is_open()) return;
    std::string line;
    int lines = 0;
    while (lines++ < kMaxSettingsLines && std::getline(in, line)) {
        if (line.size() > kMaxSettingsLineLength) continue;
        const std::size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        const std::string key = TrimSettingsToken(line.substr(0, eq));
        const std::string value = TrimSettingsToken(line.substr(eq + 1));
        bool flag = false;
        if (key == "language") {
            if (value == "es") uiState.spanishUi = true;
            else if (value == "en") uiState.spanishUi = false;
        } else if (key == "auto_scroll" && ParseSettingsBool(value, flag)) {
            uiState.autoScroll = flag;
        }
    }
}

// Writes to a temporary file first and renames it over the old one so a crash
// mid-write never leaves a truncated config behind.
inline bool SaveClientSettings(const ClientUiState& uiState, const char* path = kSettingsFileName) {
    const std::string target = path;
    const std::string temp = target + ".tmp";
    {
        std::ofstream out(temp, std::ios::trunc);
        if (!out.is_open()) return false;
        out << "language=" << (uiState.spanishUi ? "es" : "en") << "\n";
        out << "auto_scroll=" << (uiState.autoScroll ? "1" : "0") << "\n";
        out.flush();
        if (!out.good()) {
            out.close();
            std::remove(temp.c_str());
            return false;
        }
    }
    if (std::rename(temp.c_str(), target.c_str()) != 0) {
        // Windows rename() refuses to overwrite an existing file.
        std::remove(target.c_str());
        if (std::rename(temp.c_str(), target.c_str()) != 0) {
            std::remove(temp.c_str());
            return false;
        }
    }
    return true;
}

}  // namespace client_settings
