#include "client/attachment_utils.h"

#include <algorithm>
#include <cerrno>
#include <fstream>
#include <sstream>

#include <openssl/evp.h>

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

// Hex of the first `bytes` bytes of SHA-256(value).
std::string ShortSha256Hex(const std::string& value, std::size_t bytes) {
    unsigned char digest[EVP_MAX_MD_SIZE] = {};
    unsigned int digestLen = 0;
    if (EVP_Digest(value.data(), value.size(), digest, &digestLen, EVP_sha256(), nullptr) != 1) return "";
    static const char* hex = "0123456789abcdef";
    std::string out;
    for (std::size_t i = 0; i < bytes && i < digestLen; ++i) {
        out.push_back(hex[(digest[i] >> 4) & 0x0f]);
        out.push_back(hex[digest[i] & 0x0f]);
    }
    return out;
}

// Keeps cache names short (sender-chosen names can be 1 KiB): the start of the
// name plus its extension, cut on a UTF-8 character boundary.
std::string LimitFileNameLength(const std::string& name, std::size_t maxBytes) {
    if (name.size() <= maxBytes) return name;
    std::string ext;
    const std::size_t dot = name.find_last_of('.');
    if (dot != std::string::npos && name.size() - dot <= 16) ext = name.substr(dot);
    std::size_t keep = maxBytes > ext.size() ? maxBytes - ext.size() : 0;
    while (keep > 0 && (static_cast<unsigned char>(name[keep]) & 0xC0) == 0x80) --keep;
    return name.substr(0, keep) + ext;
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
                // Control characters never belong in a file name.
                if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f) c = '_';
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

std::string BuildAttachmentCachePath(const std::string& ownerUser,
                                     const std::string& attachmentId,
                                     const std::string& fileName) {
    EnsureDirectoryExists("attachments_cache");
    // Ids and names are chosen by the sender: the owner is part of the key so a
    // different user re-offering the same id+name gets a different path.
    const std::string key = ShortSha256Hex(ownerUser + "|" + attachmentId, 12);
    const std::string name = LimitFileNameLength(SanitizeAttachmentFileName(fileName), 120);
#ifdef _WIN32
    return std::string("attachments_cache\\") + key + "_" + name;
#else
    return std::string("attachments_cache/") + key + "_" + name;
#endif
}

bool IsAttachmentSafeToOpen(AttachmentKind kind, const std::string& path) {
    const std::string ext = ExtensionFromPath(path);
    if (ext.empty()) return false;
    static const char* const kImageExts[] = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp"};
    static const char* const kVideoExts[] = {".mp4", ".mkv", ".webm", ".mov", ".avi", ".m4v"};
    if (kind == AttachmentKind::Image) {
        for (const char* allowed : kImageExts)
            if (ext == allowed) return true;
    } else if (kind == AttachmentKind::Video) {
        for (const char* allowed : kVideoExts)
            if (ext == allowed) return true;
    }
    return false;  // files, executables, scripts, shortcuts...: never launched
}

bool BuildAttachmentDraftFromPath(const std::string& path, AttachmentDraft& draft, std::string& error) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input.is_open()) {
        error = "Could not open the selected file.";
        return false;
    }

    const std::streamoff fileSize = input.tellg();
    if (fileSize < 0) {
        error = "Could not determine the file size.";
        return false;
    }
    if (static_cast<std::size_t>(fileSize) > kMaxAttachmentBytes) {
        error = "Attachment too large. Current limit: " + FormatAttachmentSize(kMaxAttachmentBytes) + ".";
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
        error = "Could not open the source attachment.";
        return false;
    }

    std::ofstream output(destinationPath, std::ios::binary);
    if (!output.is_open()) {
        error = "Could not create the destination file.";
        return false;
    }

    output << input.rdbuf();
    return output.good();
}
