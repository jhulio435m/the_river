#pragma once

#include <string>
#include <vector>

#include "client/image_preview.h"

struct ClientUiState {
    char input[512] = "";
    char user[32] = "";
    char pass[32] = "";
    char newUser[32] = "";
    char newPass[32] = "";
    char attachPath[1024] = "";
    bool spanishUi = false;
    bool autoScroll = true;
    bool usersPanelOpen = false;
    bool attachPickerOpen = false;
    std::string attachPickerError;
    bool attachmentModalOpen = false;
    std::string attachmentModalOwner;
    std::string attachmentModalId;
    std::string attachmentModalError;
    bool attachmentModalLoading = false;
    ImagePreviewTexture attachmentPreviewTexture;

    // Composer helpers: sent-line history (Up/Down) and nickname completion (Tab).
    std::vector<std::string> inputHistory;
    int historyPos = -1;
    std::string historyDraft;
    std::vector<std::string> completionCandidates;
    bool focusComposer = false;
};
