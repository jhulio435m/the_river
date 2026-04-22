#include "client/platform_runtime.h"

#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

namespace {

bool FileExists(const std::string& path) {
    std::ifstream input(path, std::ios::binary);
    return input.good();
}

std::string GetEnvOrEmpty(const char* name) {
    const char* value = std::getenv(name);
    return value ? std::string(value) : std::string();
}

std::vector<std::string> LinuxDesktopFontCandidates() {
    return {
        "imgui_src/misc/fonts/Cousine-Regular.ttf",
        "imgui_src/misc/fonts/DroidSans.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        "/usr/share/fonts/TTF/DejaVuSansMono.ttf",
        "/usr/share/fonts/truetype/liberation2/LiberationMono-Regular.ttf",
        "/usr/share/fonts/liberation/LiberationMono-Regular.ttf",
        "/usr/share/fonts/noto/NotoSansMono-Regular.ttf"
    };
}

std::vector<std::string> TermuxFontCandidates() {
    const std::string prefix = GetTermuxPrefix();
    std::vector<std::string> candidates{
        "imgui_src/misc/fonts/Cousine-Regular.ttf",
        "imgui_src/misc/fonts/DroidSans.ttf"
    };

    if (!prefix.empty()) {
        candidates.push_back(prefix + "/share/fonts/TTF/DejaVuSansMono.ttf");
        candidates.push_back(prefix + "/share/fonts/truetype/dejavu/DejaVuSansMono.ttf");
        candidates.push_back(prefix + "/share/fonts/TTF/NotoSansMono-Regular.ttf");
        candidates.push_back(prefix + "/share/fonts/truetype/noto/NotoSansMono-Regular.ttf");
    }

    candidates.push_back("/system/fonts/RobotoMono-Regular.ttf");
    candidates.push_back("/system/fonts/NotoSansMono-Regular.ttf");
    candidates.push_back("/system/fonts/DroidSansMono.ttf");
    return candidates;
}

}

bool IsTermuxEnvironment() {
    const std::string termuxVersion = GetEnvOrEmpty("TERMUX_VERSION");
    if (!termuxVersion.empty()) return true;

    const std::string prefix = GetEnvOrEmpty("PREFIX");
    if (prefix.find("com.termux") != std::string::npos) return true;

    const std::string home = GetEnvOrEmpty("HOME");
    return home.find("/data/data/com.termux") != std::string::npos;
}

RuntimePlatform DetectUnixRuntimePlatform() {
    return IsTermuxEnvironment() ? RuntimePlatform::Termux : RuntimePlatform::LinuxDesktop;
}

std::string FindPreferredMonospaceFont(RuntimePlatform platform) {
    const std::vector<std::string> candidates =
        platform == RuntimePlatform::Termux ? TermuxFontCandidates() : LinuxDesktopFontCandidates();

    for (const std::string& candidate : candidates) {
        if (FileExists(candidate)) return candidate;
    }
    return "";
}

std::string GetHomeDirectory() {
    return GetEnvOrEmpty("HOME");
}

std::string GetTermuxPrefix() {
    return GetEnvOrEmpty("PREFIX");
}
