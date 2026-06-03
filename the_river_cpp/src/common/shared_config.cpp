#include "common/shared_config.h"

#include <cstdlib>

namespace river {
namespace {

std::string EnvOrDefault(const char* name, const char* fallback) {
    const char* value = std::getenv(name);
    if (value == nullptr || value[0] == '\0') return fallback;
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
