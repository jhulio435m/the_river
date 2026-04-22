#pragma once

#include <string>

enum class RuntimePlatform {
    LinuxDesktop,
    Termux
};

bool IsTermuxEnvironment();
RuntimePlatform DetectUnixRuntimePlatform();
std::string FindPreferredMonospaceFont(RuntimePlatform platform);
std::string GetHomeDirectory();
std::string GetTermuxPrefix();
