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
std::string BuildAttachmentCachePath(const std::string& attachmentId, const std::string& fileName);
bool BuildAttachmentDraftFromPath(const std::string& path, AttachmentDraft& draft, std::string& error);
bool CopyFileBinary(const std::string& sourcePath, const std::string& destinationPath, std::string& error);
