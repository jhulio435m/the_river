#include "client/platform_file_picker.h"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <string>

#include "client/attachment_utils.h"
#include "client/platform_runtime.h"

namespace fs = std::filesystem;

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

bool EnsureDirectory(const fs::path& directory, std::string& error) {
    std::error_code ec;
    fs::create_directories(directory, ec);
    if (ec) {
        error = "No se pudo preparar el directorio: " + directory.string();
        return false;
    }
    return true;
}

fs::path ResolveDownloadsDirectory() {
    const std::string home = GetHomeDirectory();
    if (home.empty()) return fs::current_path();

    const fs::path termuxDownloads = fs::path(home) / "storage" / "downloads";
    if (fs::exists(termuxDownloads)) return termuxDownloads;

    const fs::path classicDownloads = fs::path(home) / "downloads";
    if (fs::exists(classicDownloads)) return classicDownloads;

    return fs::path(home);
}

fs::path ResolveImportRoot() {
    const std::string home = GetHomeDirectory();
    if (home.empty()) return fs::current_path() / ".the_river_termux_imports";
    return fs::path(home) / ".cache" / "the_river" / "imports";
}

fs::path PickImportedFile(const fs::path& directory) {
    std::error_code ec;
    fs::path bestPath;
    fs::file_time_type bestTime{};

    for (const fs::directory_entry& entry : fs::directory_iterator(directory, ec)) {
        if (ec || !entry.is_regular_file()) continue;
        const fs::file_time_type writeTime = entry.last_write_time(ec);
        if (ec) continue;
        if (bestPath.empty() || writeTime > bestTime) {
            bestPath = entry.path();
            bestTime = writeTime;
        }
    }

    return bestPath;
}

std::string UniqueFilePath(const fs::path& baseDir, const std::string& fileName) {
    fs::path candidate = baseDir / fileName;
    if (!fs::exists(candidate)) return candidate.string();

    const fs::path stem = candidate.stem();
    const fs::path ext = candidate.extension();
    for (int index = 1; index < 1000; ++index) {
        const fs::path variant = baseDir / (stem.string() + "_" + std::to_string(index) + ext.string());
        if (!fs::exists(variant)) return variant.string();
    }
    return (baseDir / (stem.string() + "_overflow" + ext.string())).string();
}

}

bool PickAttachmentFile(AttachmentDraft& draft, std::string& error) {
    if (!CommandExists("termux-storage-get")) {
        error =
            "No se encontro termux-storage-get. Instala termux-api y usa termux-setup-storage para adjuntar archivos en Termux.";
        return false;
    }

    const fs::path importRoot = ResolveImportRoot();
    if (!EnsureDirectory(importRoot, error)) return false;

    const auto nonce = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
    const fs::path importDir = importRoot / ("pick_" + std::to_string(nonce));
    if (!EnsureDirectory(importDir, error)) return false;

    const std::string command = "termux-storage-get " + ShellQuote(importDir.string());
    if (std::system(command.c_str()) != 0) {
        error = "La seleccion de archivo en Termux fue cancelada o fallo.";
        return false;
    }

    const fs::path importedFile = PickImportedFile(importDir);
    if (importedFile.empty()) {
        error = "Termux no devolvio ningun archivo despues de la seleccion.";
        return false;
    }

    return BuildAttachmentDraftFromPath(importedFile.string(), draft, error);
}

bool PickAttachmentSavePath(const AttachmentPayload& attachment, std::string& savePath, std::string& error) {
    const fs::path downloadDir = ResolveDownloadsDirectory() / "the_river";
    if (!EnsureDirectory(downloadDir, error)) return false;

    const std::string defaultName =
        SanitizeAttachmentFileName(attachment.displayName.empty() ? "attachment.bin" : attachment.displayName);
    savePath = UniqueFilePath(downloadDir, defaultName);
    return true;
}
