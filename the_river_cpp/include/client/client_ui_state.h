#pragma once

#include <string>

#include "client/image_preview.h"

struct ClientUiState {
    char input[512] = "";
    char user[32] = "";
    char pass[32] = "";
    char newUser[32] = "";
    char newPass[32] = "";
    char attachPath[1024] = "";
    bool autoScroll = true;
    bool attachPickerOpen = false;
    std::string attachPickerError;
    bool attachmentModalOpen = false;
    std::string attachmentModalOwner;
    std::string attachmentModalId;
    std::string attachmentModalError;
    bool attachmentModalLoading = false;
    ImagePreviewTexture attachmentPreviewTexture;
};
