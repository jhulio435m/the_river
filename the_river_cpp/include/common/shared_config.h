#pragma once

#include <string>

namespace river {

inline constexpr int kServerPort = 8888;
inline constexpr int kTorProxyPort = 9050;
inline constexpr int kTorOnionPort = 80;

inline constexpr const char* kTorProxyIp = "127.0.0.1";

std::string OnionAddress();
std::string EncryptionKey();
std::string DefaultDbFile();
std::string DefaultLogFile();
std::string BindAddress();
std::string AdminUsername();
std::string AdminDefaultPassword();
std::string DefaultUserPassword();

bool IsEncryptionKeyStrong(const std::string& key);
bool HasRequiredClientConfig();
bool HasRequiredServerConfig();

}
