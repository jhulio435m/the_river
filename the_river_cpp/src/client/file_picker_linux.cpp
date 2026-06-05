#include "client/file_picker.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "client/attachment_utils.h"

namespace {

std::string TrimTrailingWhitespace(const std::string& value) {
    std::string trimmed = value;
    while (!trimmed.empty()) {
        const char c = trimmed.back();
        if (c != '\n' && c != '\r' && c != '\t' && c != ' ') break;
        trimmed.pop_back();
    }
    return trimmed;
}

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

bool RunCommandCapture(const std::string& command, std::string& output, int& exitCode) {
    output.clear();
    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        exitCode = -1;
        return false;
    }

    std::array<char, 512> buffer{};
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        output += buffer.data();
    }

    exitCode = pclose(pipe);
    if (exitCode == -1) {
        exitCode = -1;
        return false;
    }
    output = TrimTrailingWhitespace(output);
    return true;
}

bool CommandExists(const char* command) {
    const std::string probe = std::string("command -v ") + command + " >/dev/null 2>&1";
    return std::system(probe.c_str()) == 0;
}

bool TryZenityFileSelection(std::string& path) {
    int exitCode = -1;
    std::string output;
    if (!RunCommandCapture("zenity --file-selection --title='Select attachment'", output, exitCode)) return false;
    if (exitCode != 0 || output.empty()) return false;
    path = output;
    return true;
}

bool TryYadFileSelection(std::string& path) {
    int exitCode = -1;
    std::string output;
    if (!RunCommandCapture("yad --file-selection --title='Select attachment'", output, exitCode)) return false;
    if (exitCode != 0 || output.empty()) return false;
    path = output;
    return true;
}

bool TryQarmaFileSelection(std::string& path) {
    int exitCode = -1;
    std::string output;
    if (!RunCommandCapture("qarma --file-selection --title='Select attachment'", output, exitCode)) return false;
    if (exitCode != 0 || output.empty()) return false;
    path = output;
    return true;
}

bool TryMateDialogFileSelection(std::string& path) {
    int exitCode = -1;
    std::string output;
    if (!RunCommandCapture("matedialog --file-selection --title='Select attachment'", output, exitCode)) return false;
    if (exitCode != 0 || output.empty()) return false;
    path = output;
    return true;
}

bool TryKDialogFileSelection(std::string& path) {
    int exitCode = -1;
    std::string output;
    if (!RunCommandCapture("kdialog --getopenfilename .", output, exitCode)) return false;
    if (exitCode != 0 || output.empty()) return false;
    path = output;
    return true;
}

bool TryZenitySaveSelection(const std::string& fileName, std::string& path) {
    const std::string command =
        "zenity --file-selection --save --confirm-overwrite --title='Save attachment as' --filename=" +
        ShellQuote(fileName);
    int exitCode = -1;
    std::string output;
    if (!RunCommandCapture(command, output, exitCode)) return false;
    if (exitCode != 0 || output.empty()) return false;
    path = output;
    return true;
}

bool TryYadSaveSelection(const std::string& fileName, std::string& path) {
    const std::string command =
        "yad --file-selection --save --confirm-overwrite --title='Save attachment as' --filename=" +
        ShellQuote(fileName);
    int exitCode = -1;
    std::string output;
    if (!RunCommandCapture(command, output, exitCode)) return false;
    if (exitCode != 0 || output.empty()) return false;
    path = output;
    return true;
}

bool TryQarmaSaveSelection(const std::string& fileName, std::string& path) {
    const std::string command =
        "qarma --file-selection --save --confirm-overwrite --title='Save attachment as' --filename=" +
        ShellQuote(fileName);
    int exitCode = -1;
    std::string output;
    if (!RunCommandCapture(command, output, exitCode)) return false;
    if (exitCode != 0 || output.empty()) return false;
    path = output;
    return true;
}

bool TryMateDialogSaveSelection(const std::string& fileName, std::string& path) {
    const std::string command =
        "matedialog --file-selection --save --confirm-overwrite --title='Save attachment as' --filename=" +
        ShellQuote(fileName);
    int exitCode = -1;
    std::string output;
    if (!RunCommandCapture(command, output, exitCode)) return false;
    if (exitCode != 0 || output.empty()) return false;
    path = output;
    return true;
}

bool TryKDialogSaveSelection(const std::string& fileName, std::string& path) {
    const std::string command = "kdialog --getsavefilename " + ShellQuote("./" + fileName);
    int exitCode = -1;
    std::string output;
    if (!RunCommandCapture(command, output, exitCode)) return false;
    if (exitCode != 0 || output.empty()) return false;
    path = output;
    return true;
}

bool TryOpenWithCommand(const std::string& launcher, const std::string& path) {
    const std::string command =
        launcher + " " + ShellQuote(path) + " >/dev/null 2>&1 &";
    return std::system(command.c_str()) == 0;
}

}  // namespace

bool PickAttachmentFile(AttachmentDraft& draft, std::string& error) {
    std::string selectedPath;
    if (CommandExists("zenity")) {
        if (!TryZenityFileSelection(selectedPath)) return false;
        return BuildAttachmentDraftFromPath(selectedPath, draft, error);
    }
    if (CommandExists("yad")) {
        if (!TryYadFileSelection(selectedPath)) return false;
        return BuildAttachmentDraftFromPath(selectedPath, draft, error);
    }
    if (CommandExists("qarma")) {
        if (!TryQarmaFileSelection(selectedPath)) return false;
        return BuildAttachmentDraftFromPath(selectedPath, draft, error);
    }
    if (CommandExists("matedialog")) {
        if (!TryMateDialogFileSelection(selectedPath)) return false;
        return BuildAttachmentDraftFromPath(selectedPath, draft, error);
    }
    if (CommandExists("kdialog")) {
        if (!TryKDialogFileSelection(selectedPath)) return false;
        return BuildAttachmentDraftFromPath(selectedPath, draft, error);
    }

    error = "No supported file picker was found. Install zenity, yad, qarma, matedialog, or kdialog to attach files.";
    return false;
}

bool PickAttachmentSavePath(const AttachmentPayload& attachment, std::string& savePath, std::string& error) {
    const std::string defaultName =
        SanitizeAttachmentFileName(attachment.displayName.empty() ? "attachment.bin" : attachment.displayName);
    if (CommandExists("zenity")) {
        if (TryZenitySaveSelection(defaultName, savePath)) return true;
        return false;
    }
    if (CommandExists("yad")) {
        if (TryYadSaveSelection(defaultName, savePath)) return true;
        return false;
    }
    if (CommandExists("qarma")) {
        if (TryQarmaSaveSelection(defaultName, savePath)) return true;
        return false;
    }
    if (CommandExists("matedialog")) {
        if (TryMateDialogSaveSelection(defaultName, savePath)) return true;
        return false;
    }
    if (CommandExists("kdialog")) {
        if (TryKDialogSaveSelection(defaultName, savePath)) return true;
        return false;
    }

    error = "No supported file picker was found. Install zenity, yad, qarma, matedialog, or kdialog to choose a save path.";
    return false;
}

bool OpenPathWithShell(const std::string& path) {
    if (CommandExists("xdg-open") && TryOpenWithCommand("xdg-open", path)) return true;
    if (CommandExists("gio") && TryOpenWithCommand("gio open", path)) return true;
    if (CommandExists("kioclient5") && TryOpenWithCommand("kioclient5 exec", path)) return true;
    if (CommandExists("kioclient") && TryOpenWithCommand("kioclient exec", path)) return true;
    if (CommandExists("exo-open") && TryOpenWithCommand("exo-open", path)) return true;
    if (CommandExists("gvfs-open") && TryOpenWithCommand("gvfs-open", path)) return true;
    return false;
}
