#pragma once

#include <string>

namespace river {

inline constexpr int kServerPort = 8888;
inline constexpr int kTorProxyPort = 9050;
inline constexpr int kTorOnionPort = 80;

inline constexpr const char* kTorProxyIp = "127.0.0.1";

// Server listen port: THE_RIVER_PORT (1..65535), default kServerPort (8888).
// Server only; clients always reach the server through its onion port.
int ServerPort();
// Client SOCKS5 proxy port: THE_RIVER_TOR_PROXY_PORT (1..65535), default
// kTorProxyPort (9050). Used by the GUI client and the admin console.
int TorProxyPort();

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
