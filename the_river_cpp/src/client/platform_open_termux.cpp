#include "client/platform_launcher.h"

#include <cstdlib>
#include <string>

namespace {

std::string ShellQuote(const std::string& value) {
    std::string quoted = "'";
    for (char c : value) {
        if (c == '\'') {
            quoted += "'\\''";
        } else {
            quoted.push_back(c);
        }
    }
    quoted.push_back('\'');
    return quoted;
}

bool CommandExists(const char* command) {
    const std::string probe = std::string("command -v ") + command + " >/dev/null 2>&1";
    return std::system(probe.c_str()) == 0;
}

bool RunDetached(const std::string& command) {
    return std::system((command + " >/dev/null 2>&1 &").c_str()) == 0;
}

}

bool OpenPathWithShell(const std::string& path) {
    const std::string quotedPath = ShellQuote(path);
    if (CommandExists("termux-open") && RunDetached("termux-open " + quotedPath)) return true;
    if (CommandExists("xdg-open") && RunDetached("xdg-open " + quotedPath)) return true;
    if (CommandExists("gio") && RunDetached("gio open " + quotedPath)) return true;
    return false;
}
