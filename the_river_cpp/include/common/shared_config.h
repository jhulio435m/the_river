#pragma once

namespace river {

inline constexpr int kServerPort = 8888;
inline constexpr int kTorProxyPort = 9050;
inline constexpr int kTorOnionPort = 80;

inline constexpr const char* kTorProxyIp = "127.0.0.1";
inline constexpr const char* kOnionAddress = "ag45wpipb6zrbw6l7lhg5hsoph6ocdqenomdbpn4hsuqxqjhc7qyopid.onion";
inline constexpr const char* kAesKey = "RIVER_SECURE_KEY";
inline constexpr const char* kDefaultDbFile = "secure_river.db";
inline constexpr const char* kDefaultLogFile = "chat_history.log";
inline constexpr const char* kAdminUsername = "admin";
inline constexpr const char* kAdminDefaultPassword = "176132";
inline constexpr const char* kDefaultUserPassword = "river123";

}
