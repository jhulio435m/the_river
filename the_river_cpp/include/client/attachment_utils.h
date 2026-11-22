#pragma once

#include <string>

#include "client/attachment_types.h"

std::string AttachmentKindToLabel(AttachmentKind kind);
std::string AttachmentStateToLabel(AttachmentTransferState state);
std::string GuessMimeTypeFromPath(const std::string& path);
AttachmentKind GuessAttachmentKindFromPath(const std::string& path);
std::string ExtractFileNameFromPath(const std::string& path);
std::string SanitizeAttachmentFileName(const std::string& fileName);
std::string FormatAttachmentSize(std::size_t sizeBytes);
// attachments_cache/<hash(owner|id)>_<sanitized name>: distinct per owner.
std::string BuildAttachmentCachePath(const std::string& ownerUser,
                                     const std::string& attachmentId,
                                     const std::string& fileName);
// True only when `path` has an image (png jpg jpeg gif bmp webp) or video
// (mp4 mkv webm mov avi m4v) extension matching `kind`. Anything else must not
// be handed to the system shell ("Open"); offer Save As instead.
bool IsAttachmentSafeToOpen(AttachmentKind kind, const std::string& path);
bool BuildAttachmentDraftFromPath(const std::string& path, AttachmentDraft& draft, std::string& error);
bool CopyFileBinary(const std::string& sourcePath, const std::string& destinationPath, std::string& error);
