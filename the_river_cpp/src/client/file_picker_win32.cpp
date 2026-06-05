#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>
#include <cstdint>
#include <cstring>

#include "client/file_picker.h"

#include "client/attachment_utils.h"

bool PickAttachmentFile(AttachmentDraft& draft, std::string& error) {
    char filePath[MAX_PATH] = "";
    OPENFILENAMEA ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = sizeof(filePath);
    ofn.lpstrFilter =
        "Archivos soportados\0*.png;*.jpg;*.jpeg;*.gif;*.bmp;*.webp;*.mp4;*.webm;*.avi;*.mov;*.mkv;*.txt;*.log;*.pdf;*.zip;*.json;*.md\0"
        "All files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;

    if (!GetOpenFileNameA(&ofn)) {
        const DWORD dialogError = CommDlgExtendedError();
        if (dialogError != 0) error = "Could not open the file picker.";
        return false;
    }

    return BuildAttachmentDraftFromPath(filePath, draft, error);
}

bool PickAttachmentSavePath(const AttachmentPayload& attachment, std::string& savePath, std::string& error) {
    char filePath[MAX_PATH] = "";
    std::strncpy(filePath, attachment.displayName.c_str(), sizeof(filePath) - 1);

    OPENFILENAMEA ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFile = filePath;
    ofn.nMaxFile = sizeof(filePath);
    ofn.lpstrFilter = "All files\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;

    if (!GetSaveFileNameA(&ofn)) {
        const DWORD dialogError = CommDlgExtendedError();
        if (dialogError != 0) error = "Could not open the Save As dialog.";
        return false;
    }

    savePath = filePath;
    return true;
}

bool OpenPathWithShell(const std::string& path) {
    return reinterpret_cast<std::intptr_t>(ShellExecuteA(nullptr, "open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL)) > 32;
}
