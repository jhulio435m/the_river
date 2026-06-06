#pragma once

#include <cstddef>
#include <string>

enum class AttachmentKind {
    File,
    Image,
    Video
};

enum class AttachmentTransferState {
    Available,
    Requested,
    Received,
    Failed
};

struct AttachmentDraft {
    std::string localPath;
    std::string displayName;
    std::string mimeType;
    AttachmentKind kind = AttachmentKind::File;
    std::size_t sizeBytes = 0;
};

struct AttachmentPayload {
    std::string id;
    std::string ownerUser;
    std::string displayName;
    std::string mimeType;
    std::string contentSha256;
    std::string localPath;
    AttachmentKind kind = AttachmentKind::File;
    std::size_t sizeBytes = 0;
    AttachmentTransferState state = AttachmentTransferState::Available;
};

constexpr std::size_t kMaxAttachmentBytes = 12 * 1024 * 1024;
constexpr std::size_t kAttachmentChunkChars = 2048;
