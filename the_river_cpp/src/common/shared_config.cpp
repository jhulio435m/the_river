#include "common/shared_config.h"

#include <cstdlib>
#include <fstream>
#include <map>

namespace river {
namespace {

std::map<std::string, std::string> LoadRuntimeEnvFile() {
    std::map<std::string, std::string> values;
    std::ifstream input("tor_data/runtime.env");
    if (!input.is_open()) input.open(".env.local");
    if (!input.is_open()) return values;

    std::string line;
    while (std::getline(input, line)) {
        if (line.empty() || line[0] == '#') continue;
        const std::size_t sep = line.find('=');
        if (sep == std::string::npos) continue;

        std::string key = line.substr(0, sep);
        std::string value = line.substr(sep + 1);
        if (value.size() >= 2 &&
            ((value.front() == '"' && value.back() == '"') ||
             (value.front() == '\'' && value.back() == '\''))) {
            value = value.substr(1, value.size() - 2);
        }
        values[key] = value;
    }
    return values;
}

std::string FileOrDefault(const char* name, const char* fallback) {
    static const std::map<std::string, std::string> fileValues = LoadRuntimeEnvFile();
    auto it = fileValues.find(name);
    if (it == fileValues.end() || it->second.empty()) return fallback;
    return it->second;
}

std::string EnvOrDefault(const char* name, const char* fallback) {
    const char* value = std::getenv(name);
    if (value == nullptr || value[0] == '\0') return FileOrDefault(name, fallback);
    return value;
}

}  // namespace

std::string OnionAddress() {
    return EnvOrDefault("THE_RIVER_ONION", "");
}

std::string EncryptionKey() {
    return EnvOrDefault("THE_RIVER_AES_KEY", "");
}

std::string DefaultDbFile() {
    return EnvOrDefault("THE_RIVER_DB", "secure_river.db");
}

std::string DefaultLogFile() {
    return EnvOrDefault("THE_RIVER_LOG", "chat_history.log");
}

std::string BindAddress() {
    return EnvOrDefault("THE_RIVER_BIND_ADDR", "127.0.0.1");
}

std::string AdminUsername() {
    return EnvOrDefault("THE_RIVER_ADMIN_USER", "admin");
}

std::string AdminDefaultPassword() {
    return EnvOrDefault("THE_RIVER_ADMIN_BOOTSTRAP_PASSWORD", "");
}

std::string DefaultUserPassword() {
    return EnvOrDefault("THE_RIVER_NEW_USER_PASSWORD", "");
}

bool HasRequiredClientConfig() {
    return !OnionAddress().empty() && !EncryptionKey().empty();
}

bool HasRequiredServerConfig() {
    return !EncryptionKey().empty() && !AdminDefaultPassword().empty() && !DefaultUserPassword().empty();
}

}  // namespace river
