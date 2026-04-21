#include "client/attachment_utils.h"

#include <algorithm>
#include <cerrno>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#include <direct.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

namespace {

std::string ToLowerCopy(const std::string& value) {
    std::string lowered = value;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) {
        if (c >= 'A' && c <= 'Z') return static_cast<char>(c - 'A' + 'a');
        return static_cast<char>(c);
    });
    return lowered;
}

std::string ExtensionFromPath(const std::string& path) {
    const std::string fileName = path.substr(path.find_last_of("/\\") + 1);
    const std::size_t dot = fileName.find_last_of('.');
    if (dot == std::string::npos) return "";
    return ToLowerCopy(fileName.substr(dot));
}

bool EnsureDirectoryExists(const char* directory) {
#ifdef _WIN32
    const int rc = _mkdir(directory);
    return rc == 0 || errno == EEXIST;
#else
    const int rc = mkdir(directory, 0755);
    return rc == 0 || errno == EEXIST;
#endif
}

}  // namespace

std::string AttachmentKindToLabel(AttachmentKind kind) {
    switch (kind) {
        case AttachmentKind::Image: return "IMG";
        case AttachmentKind::Video: return "VID";
        case AttachmentKind::File: return "FILE";
    }
    return "FILE";
}

std::string AttachmentStateToLabel(AttachmentTransferState state) {
    switch (state) {
        case AttachmentTransferState::Available: return "AVAILABLE";
        case AttachmentTransferState::Requested: return "REQUESTED";
        case AttachmentTransferState::Received: return "RECEIVED";
        case AttachmentTransferState::Failed: return "FAILED";
    }
    return "UNKNOWN";
}

std::string GuessMimeTypeFromPath(const std::string& path) {
    const std::string ext = ExtensionFromPath(path);
    if (ext == ".png") return "image/png";
    if (ext == ".jpg" || ext == ".jpeg") return "image/jpeg";
    if (ext == ".gif") return "image/gif";
    if (ext == ".bmp") return "image/bmp";
    if (ext == ".webp") return "image/webp";
    if (ext == ".mp4") return "video/mp4";
    if (ext == ".webm") return "video/webm";
    if (ext == ".avi") return "video/x-msvideo";
    if (ext == ".mov") return "video/quicktime";
    if (ext == ".mkv") return "video/x-matroska";
    if (ext == ".txt" || ext == ".log") return "text/plain";
    if (ext == ".md") return "text/markdown";
    if (ext == ".json") return "application/json";
    if (ext == ".pdf") return "application/pdf";
    if (ext == ".zip") return "application/zip";
    if (ext == ".rar") return "application/vnd.rar";
    if (ext == ".7z") return "application/x-7z-compressed";
    if (ext == ".cpp" || ext == ".h" || ext == ".hpp" || ext == ".c") return "text/x-source";
    return "application/octet-stream";
}

AttachmentKind GuessAttachmentKindFromPath(const std::string& path) {
    const std::string mime = GuessMimeTypeFromPath(path);
    if (mime.rfind("image/", 0) == 0) return AttachmentKind::Image;
    if (mime.rfind("video/", 0) == 0) return AttachmentKind::Video;
    return AttachmentKind::File;
}

std::string ExtractFileNameFromPath(const std::string& path) {
    const std::size_t separator = path.find_last_of("/\\");
    return separator == std::string::npos ? path : path.substr(separator + 1);
}

std::string SanitizeAttachmentFileName(const std::string& fileName) {
    std::string sanitized = fileName;
    for (char& c : sanitized) {
        switch (c) {
            case '<':
            case '>':
            case ':':
            case '"':
            case '/':
            case '\\':
            case '|':
            case '?':
            case '*':
                c = '_';
                break;
            default:
                break;
        }
    }
    if (sanitized.empty()) sanitized = "attachment.bin";
    return sanitized;
}

std::string FormatAttachmentSize(std::size_t sizeBytes) {
    std::ostringstream out;
    if (sizeBytes >= 1024 * 1024) {
        out.setf(std::ios::fixed);
        out.precision(2);
        out << (static_cast<double>(sizeBytes) / (1024.0 * 1024.0)) << " MB";
    } else if (sizeBytes >= 1024) {
        out.setf(std::ios::fixed);
        out.precision(1);
        out << (static_cast<double>(sizeBytes) / 1024.0) << " KB";
    } else {
        out << sizeBytes << " B";
    }
    return out.str();
}

std::string BuildAttachmentCachePath(const std::string& attachmentId, const std::string& fileName) {
    EnsureDirectoryExists("attachments_cache");
#ifdef _WIN32
    return std::string("attachments_cache\\") + attachmentId + "_" + SanitizeAttachmentFileName(fileName);
#else
    return std::string("attachments_cache/") + attachmentId + "_" + SanitizeAttachmentFileName(fileName);
#endif
}

bool BuildAttachmentDraftFromPath(const std::string& path, AttachmentDraft& draft, std::string& error) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input.is_open()) {
        error = "No se pudo abrir el archivo seleccionado.";
        return false;
    }

    const std::streamoff fileSize = input.tellg();
    if (fileSize < 0) {
        error = "No se pudo determinar el tamano del archivo.";
        return false;
    }
    if (static_cast<std::size_t>(fileSize) > kMaxAttachmentBytes) {
        error = "Adjunto demasiado grande. Limite actual: " + FormatAttachmentSize(kMaxAttachmentBytes) + ".";
        return false;
    }

    draft.localPath = path;
    draft.displayName = ExtractFileNameFromPath(path);
    draft.mimeType = GuessMimeTypeFromPath(path);
    draft.kind = GuessAttachmentKindFromPath(path);
    draft.sizeBytes = static_cast<std::size_t>(fileSize);
    return true;
}

bool CopyFileBinary(const std::string& sourcePath, const std::string& destinationPath, std::string& error) {
    std::ifstream input(sourcePath, std::ios::binary);
    if (!input.is_open()) {
        error = "No se pudo abrir el adjunto fuente.";
        return false;
    }

    std::ofstream output(destinationPath, std::ios::binary);
    if (!output.is_open()) {
        error = "No se pudo crear el archivo destino.";
        return false;
    }

    output << input.rdbuf();
    return output.good();
}
