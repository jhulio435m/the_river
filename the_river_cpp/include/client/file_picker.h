#pragma once

#include <string>

#include "client/attachment_types.h"

bool PickAttachmentFile(AttachmentDraft& draft, std::string& error);
bool PickAttachmentSavePath(const AttachmentPayload& attachment, std::string& savePath, std::string& error);
bool OpenPathWithShell(const std::string& path);
