#include "client/ui_sections.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

#include "client/app_ui.h"
#include "client/attachment_utils.h"
#include "client/chat_client.h"
#include "client/chat_state.h"
#include "client/command_processor.h"
#include "client/file_picker.h"
#include "client/image_preview.h"

namespace {

std::string TrimCopy(const char* value) {
    std::string text = value ? value : "";
    const std::size_t start = text.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    const std::size_t end = text.find_last_not_of(" \t\r\n");
    return text.substr(start, end - start + 1);
}

void DrawInfoBand(const char* label, const std::string& value, const ImVec4& color) {
    const float wrapWidth = ImGui::GetContentRegionAvail().x - 18.0f;
    const float compactScale = 0.72f;
    ImGui::SetWindowFontScale(compactScale);
    const float labelHeight = ImGui::GetTextLineHeight();
    const float bodyHeight = ImGui::CalcTextSize(value.c_str(), nullptr, false, wrapWidth / compactScale).y;
    ImGui::SetWindowFontScale(1.0f);

    const float boxHeight = labelHeight + bodyHeight + 28.0f;
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(color.x * 0.12f, color.y * 0.12f, color.z * 0.12f, 0.95f));
    ImGui::BeginChild(label, ImVec2(0, boxHeight), true, ImGuiWindowFlags_NoScrollbar);
    ImGui::SetWindowFontScale(compactScale);
    ImGui::TextColored(color, "%s", label);
    ImGui::TextWrapped("%s", value.c_str());
    ImGui::SetWindowFontScale(1.0f);
    ImGui::EndChild();
    ImGui::PopStyleColor();
}

void DrawErrorBanner(const std::string& error) {
    if (error.empty()) return;
    const float wrapWidth = ImGui::GetContentRegionAvail().x - 18.0f;
    const float compactScale = 0.72f;
    ImGui::SetWindowFontScale(compactScale);
    const float titleHeight = ImGui::GetTextLineHeight();
    const float bodyHeight = ImGui::CalcTextSize(error.c_str(), nullptr, false, wrapWidth / compactScale).y;
    ImGui::SetWindowFontScale(1.0f);

    const float boxHeight = titleHeight + bodyHeight + 34.0f;
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.24f, 0.03f, 0.02f, 0.96f));
    ImGui::BeginChild("##error_banner", ImVec2(0, boxHeight), true, ImGuiWindowFlags_NoScrollbar);
    ImGui::SetWindowFontScale(compactScale);
    ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.32f, 1.0f), "ULTIMO ERROR");
    ImGui::Separator();
    ImGui::TextWrapped("%s", error.c_str());
    ImGui::SetWindowFontScale(1.0f);
    ImGui::EndChild();
    ImGui::PopStyleColor();
}

void RenderConnectionScreen(ChatState& state,
                            float width,
                            float height,
                            ConnState connState,
                            const UiPalette& palette) {
    const std::string statusDetail = state.StatusDetail();
    const float t = static_cast<float>(ImGui::GetTime());
    ImGui::SetCursorPos(ImVec2(0, 0));
    ImGui::BeginChild("##IntroAnim", ImVec2(width, height), false,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoInputs | ImGuiWindowFlags_NoBackground);

    for (int y = 0; y < static_cast<int>(height); y += 24) {
        for (int x = 0; x < static_cast<int>(width); x += 32) {
            const float noise = std::sin(x * 0.05f + t * 2.5f) * std::cos(y * 0.05f - t * 1.8f);
            if (noise > 0.35f) {
                ImGui::SetCursorPos(ImVec2(static_cast<float>(x), static_cast<float>(y)));
                const ImVec4 blockCol =
                    (std::sin(t * 12.0f + x) > 0) ? ImVec4(0.8f, 0.0f, 0.0f, 0.35f) : ImVec4(0.0f, 0.8f, 0.4f, 0.35f);
                ImGui::TextColored(blockCol, "█");
            }
        }
    }
    ImGui::EndChild();

    ImGui::SetCursorPos(ImVec2(width * 0.5f - 250.0f, height * 0.5f - 70.0f));
    ImGui::BeginChild("##ConnectingPanel", ImVec2(500, 160), true);
    ImGui::TextColored(palette.bbsLime, "UPLINK STATUS: %s", UiStatusLabel(connState));
    ImGui::Separator();
    ImGui::TextWrapped("%s", statusDetail.c_str());
    ImGui::EndChild();
}

void RenderCredentialChangeScreen(ChatClient& client,
                                  ChatState& state,
                                  ClientUiState& uiState,
                                  float width,
                                  float height,
                                  ConnState connState,
                                  const UiPalette& palette) {
    const std::string statusDetail = state.StatusDetail();
    const std::string lastError = state.LastError();
    const bool credentialPending = state.IsCredentialChangePending();

    ImGui::SetCursorPos(ImVec2(width * 0.5f - 250.0f, height * 0.5f - 180.0f));
    ImGui::BeginChild("##FirstLoginPanel", ImVec2(500, 360), true);
    ImGui::TextColored(palette.bbsMagenta, "PRIMER ACCESO // CAMBIO OBLIGATORIO");
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::TextWrapped("Debes definir un nuevo identificador y una nueva clave antes de entrar al chat.");
    ImGui::Spacing();

    bool submitCredentialChange = false;
    bool focusNewPass = false;
    ImGui::Text("NEW IDENT:");
    ImGui::SameLine();
    focusNewPass = ImGui::InputText("##NEW_ID", uiState.newUser, 32, ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::Text("NEW KEY :");
    ImGui::SameLine();
    if (focusNewPass) ImGui::SetKeyboardFocusHere();
    submitCredentialChange |= ImGui::InputText("##NEW_PW", uiState.newPass, 32,
                                               ImGuiInputTextFlags_Password | ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::Spacing();

    const std::string newUser = TrimCopy(uiState.newUser);
    const std::string newPass = TrimCopy(uiState.newPass);
    const bool canSubmitCredentialChange = !newUser.empty() && !newPass.empty() && !credentialPending;

    if (!canSubmitCredentialChange) ImGui::BeginDisabled();
    if (ImGui::Button("ACTUALIZAR CREDENCIALES", ImVec2(-1, 42))) submitCredentialChange = true;
    if (!canSubmitCredentialChange) ImGui::EndDisabled();

    if (submitCredentialChange && canSubmitCredentialChange) client.SendFirstLoginChange(newUser, newPass);

    ImGui::Spacing();
    DrawInfoBand("UPLINK STATUS", statusDetail, UiStatusColor(connState));
    DrawErrorBanner(lastError);
    ImGui::EndChild();
}

void RenderLoginScreen(ChatClient& client,
                       ChatState& state,
                       ClientUiState& uiState,
                       float width,
                       float height,
                       ConnState connState,
                       const UiPalette& palette) {
    const std::string statusDetail = state.StatusDetail();
    const std::string lastError = state.LastError();
    const bool authPending = state.IsAuthActionPending();

    ImGui::SetCursorPos(ImVec2(width * 0.5f - 220.0f, height * 0.5f - 150.0f));
    ImGui::BeginChild("##AccessPanel", ImVec2(440, 300), true);
    ImGui::TextColored(palette.bbsMagenta, "CHARON SUITE // ACCESS TERMINAL");
    ImGui::Separator();
    ImGui::Spacing();

    bool submitLogin = false;
    bool focusLoginPass = false;
    ImGui::Text("IDENT:");
    ImGui::SameLine();
    focusLoginPass = ImGui::InputText("##ID", uiState.user, 32, ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::Text("KEY  :");
    ImGui::SameLine();
    if (focusLoginPass) ImGui::SetKeyboardFocusHere();
    submitLogin |= ImGui::InputText("##PW", uiState.pass, 32,
                                    ImGuiInputTextFlags_Password | ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::Spacing();

    const std::string user = TrimCopy(uiState.user);
    const std::string pass = TrimCopy(uiState.pass);
    const bool canSubmit = !user.empty() && !pass.empty() && !authPending;

    if (!canSubmit) ImGui::BeginDisabled();
    if (ImGui::Button("ESTABLISH UPLINK", ImVec2(-1, 40))) submitLogin = true;
    if (!canSubmit) ImGui::EndDisabled();

    if (submitLogin && canSubmit) client.SendLogin(user, pass);

    ImGui::Spacing();
    DrawInfoBand("UPLINK STATUS", statusDetail, UiStatusColor(connState));
    DrawErrorBanner(lastError);
    ImGui::EndChild();
}

bool RenderAttachmentLine(const LogEntry& entry, bool isMe, const UiPalette& palette) {
    const ImVec4 titleColor = isMe ? palette.bbsMagenta : palette.bbsLime;
    const std::string label =
        "<" + entry.user + "> [" + AttachmentKindToLabel(entry.attachment.kind) + "] " +
        entry.attachment.displayName + " (" + FormatAttachmentSize(entry.attachment.sizeBytes) + ")";
    ImGui::PushStyleColor(ImGuiCol_Text, titleColor);
    const bool clicked = ImGui::Selectable(
        (label + "##att_" + entry.user + "_" + entry.attachment.id).c_str(),
        false,
        ImGuiSelectableFlags_AllowDoubleClick);
    ImGui::PopStyleColor();
    return clicked;
}

void HandleAttachButton(ChatClient& client, ChatState& state) {
    AttachmentDraft draft;
    std::string pickerError;
    if (!PickAttachmentFile(draft, pickerError)) {
        if (!pickerError.empty()) state.AddSystemLog("SYSTEM: " + pickerError);
        return;
    }

    const std::string currentIdentity = state.CurrentIdentity();
    if (currentIdentity.empty()) {
        state.AddSystemLog("SYSTEM: No hay identidad autenticada para adjuntar archivos.");
        return;
    }

    if (!client.SendAttachment(currentIdentity, draft)) {
        state.AddSystemLog("SYSTEM: No se pudo enviar el adjunto seleccionado.");
    }
}

void ResetAttachmentModal(ClientUiState& uiState) {
    uiState.attachmentModalOpen = false;
    uiState.attachmentModalOwner.clear();
    uiState.attachmentModalId.clear();
    uiState.attachmentModalError.clear();
    uiState.attachmentModalLoading = false;
    ReleaseImagePreviewTexture(uiState.attachmentPreviewTexture);
}

void SaveAttachmentAs(ChatClient& client, ChatState& state, const AttachmentPayload& attachment) {
    if (!attachment.localPath.empty()) {
        if (!OpenPathWithShell(attachment.localPath))
            state.AddSystemLog("SYSTEM: No se pudo abrir el archivo local.");
        return;
    }

    std::string savePath;
    std::string saveError;
    if (!PickAttachmentSavePath(attachment, savePath, saveError)) {
        if (!saveError.empty()) state.AddSystemLog("SYSTEM: " + saveError);
        return;
    }

    if (!client.RequestAttachment(attachment, savePath, "save"))
        state.AddSystemLog("SYSTEM: No se pudo solicitar el adjunto.");
}

void OpenAttachmentModal(ChatClient& client,
                         ChatState& state,
                         ClientUiState& uiState,
                         const AttachmentPayload& attachment) {
    uiState.attachmentModalOpen = true;
    uiState.attachmentModalOwner = attachment.ownerUser;
    uiState.attachmentModalId = attachment.id;
    uiState.attachmentModalError.clear();
    uiState.attachmentModalLoading = attachment.localPath.empty() && attachment.ownerUser != state.CurrentIdentity();
    ReleaseImagePreviewTexture(uiState.attachmentPreviewTexture);

    if (attachment.localPath.empty() && attachment.ownerUser != state.CurrentIdentity()) {
        const std::string previewPath = BuildAttachmentCachePath(attachment.id, attachment.displayName);
        if (!client.RequestAttachment(attachment, previewPath, "preview")) {
            uiState.attachmentModalLoading = false;
            uiState.attachmentModalError = state.LastError();
        }
    }
}

void HandleAttachmentClick(ChatClient& client,
                           ChatState& state,
                           ClientUiState& uiState,
                           const AttachmentPayload& attachment) {
    if (attachment.kind == AttachmentKind::File) {
        SaveAttachmentAs(client, state, attachment);
        return;
    }
    OpenAttachmentModal(client, state, uiState, attachment);
}

void RenderAttachmentModal(ChatClient& client, ChatState& state, ClientUiState& uiState) {
    if (!uiState.attachmentModalOpen) return;

    AttachmentPayload attachment;
    if (!state.FindAttachment(uiState.attachmentModalOwner, uiState.attachmentModalId, attachment)) {
        ResetAttachmentModal(uiState);
        return;
    }

    if (!ImGui::IsPopupOpen("##AttachmentPreview")) ImGui::OpenPopup("##AttachmentPreview");
    bool keepOpen = true;
    if (ImGui::BeginPopupModal("##AttachmentPreview", &keepOpen, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("[%s] %s", AttachmentKindToLabel(attachment.kind).c_str(), attachment.displayName.c_str());
        ImGui::Separator();
        ImGui::Text("Owner: %s", attachment.ownerUser.c_str());
        ImGui::Text("Type : %s", attachment.mimeType.c_str());
        ImGui::Text("Size : %s", FormatAttachmentSize(attachment.sizeBytes).c_str());
        ImGui::Spacing();

        uiState.attachmentModalLoading = attachment.localPath.empty();
        if (uiState.attachmentModalLoading) {
            ImGui::TextColored(ImVec4(0.9f, 0.9f, 0.4f, 1.0f), "Receiving attachment...");
        } else if (!uiState.attachmentModalError.empty()) {
            ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.32f, 1.0f), "%s", uiState.attachmentModalError.c_str());
        } else if (attachment.kind == AttachmentKind::Image) {
            std::string previewError;
            if (EnsureImagePreviewTexture(attachment.localPath, uiState.attachmentPreviewTexture, previewError)) {
                const ImVec2 display = ImGui::GetIO().DisplaySize;
                const float maxWidth = (display.x * 0.72f < 720.0f) ? display.x * 0.72f : 720.0f;
                const float maxHeight = (display.y * 0.60f < 480.0f) ? display.y * 0.60f : 480.0f;
                float imageWidth = static_cast<float>(uiState.attachmentPreviewTexture.width);
                float imageHeight = static_cast<float>(uiState.attachmentPreviewTexture.height);
                const float widthScale = maxWidth / imageWidth;
                const float heightScale = maxHeight / imageHeight;
                const float scale = std::min(1.0f, std::min(widthScale, heightScale));
                imageWidth *= scale;
                imageHeight *= scale;
                ImGui::Image((ImTextureID)(intptr_t)(uiState.attachmentPreviewTexture.textureId),
                             ImVec2(imageWidth, imageHeight));
            } else {
                uiState.attachmentModalError = previewError;
            }
        } else {
            ImGui::TextWrapped("Video ready. Use Open to launch it with the system player.");
        }

        ImGui::Spacing();
        if (attachment.kind == AttachmentKind::Video && !attachment.localPath.empty()) {
            if (ImGui::Button("Open", ImVec2(110, 0))) {
                if (!OpenPathWithShell(attachment.localPath))
                    uiState.attachmentModalError = "No se pudo abrir el video.";
            }
            ImGui::SameLine();
        }
        if (!attachment.localPath.empty()) {
            if (ImGui::Button("Save As...", ImVec2(110, 0))) {
                std::string savePath;
                std::string saveError;
                if (PickAttachmentSavePath(attachment, savePath, saveError)) {
                    if (!CopyFileBinary(attachment.localPath, savePath, saveError))
                        uiState.attachmentModalError = saveError;
                } else if (!saveError.empty()) {
                    uiState.attachmentModalError = saveError;
                }
            }
            ImGui::SameLine();
        }
        if (ImGui::Button("Close", ImVec2(110, 0))) keepOpen = false;
        ImGui::EndPopup();
    }

    if (!keepOpen) ResetAttachmentModal(uiState);
}

}  // namespace

const char* UiStatusLabel(ConnState state) {
    switch (state) {
        case ConnState::DISCONNECTED: return "OFFLINE";
        case ConnState::CONNECTING: return "NEGOCIANDO TOR";
        case ConnState::TOR_READY: return "TOR LISTO";
        case ConnState::AUTHENTICATING: return "AUTENTICANDO";
        case ConnState::FIRST_LOGIN_REQUIRED: return "PRIMER ACCESO";
        case ConnState::UPDATING_CREDENTIALS: return "ACTUALIZANDO";
        case ConnState::RECONNECTING: return "RECONECTANDO";
        case ConnState::AUTHENTICATED: return "SECURE";
    }
    return "UNKNOWN";
}

ImVec4 UiStatusColor(ConnState state) {
    switch (state) {
        case ConnState::DISCONNECTED: return ImVec4(0.95f, 0.25f, 0.12f, 1.0f);
        case ConnState::CONNECTING: return ImVec4(0.12f, 0.76f, 0.98f, 1.0f);
        case ConnState::TOR_READY: return ImVec4(0.00f, 0.92f, 0.58f, 1.0f);
        case ConnState::AUTHENTICATING: return ImVec4(0.99f, 0.85f, 0.20f, 1.0f);
        case ConnState::FIRST_LOGIN_REQUIRED: return ImVec4(1.00f, 0.68f, 0.22f, 1.0f);
        case ConnState::UPDATING_CREDENTIALS: return ImVec4(0.96f, 0.72f, 0.28f, 1.0f);
        case ConnState::RECONNECTING: return ImVec4(0.65f, 0.82f, 1.0f, 1.0f);
        case ConnState::AUTHENTICATED: return ImVec4(0.00f, 1.00f, 0.45f, 1.0f);
    }
    return ImVec4(1, 1, 1, 1);
}

void RenderHeaderBar(const ChatState& state, float width, const UiPalette& palette) {
    ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(0, 0), ImVec2(width, 42), ImColor(palette.bbsBlue));
    ImGui::SetCursorPos(ImVec2(10, 6));
    ImGui::Text("Active Users %d <SECURE UPLINK>", state.ActiveUserCount());

    ImGui::SetCursorPos(ImVec2(width - 320, 2));
    ImGui::TextDisabled("MBmon for MBSE BBS version 0.37.6");
    ImGui::SetCursorPos(ImVec2(width - 320, 18));
    ImGui::TextColored(ImVec4(1, 1, 0, 1), "Copyright (C) 1997-2026");
    ImGui::SameLine();
    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.8f, 0, 0, 1));
    ImGui::BeginChild("##Busy", ImVec2(40, 18), false);
    ImGui::Text("Busy");
    ImGui::EndChild();
    ImGui::PopStyleColor();
}

void RenderUnauthenticatedUi(ChatClient& client,
                             ChatState& state,
                             ClientUiState& uiState,
                             float width,
                             float height,
                             const UiPalette& palette) {
    const ConnState connState = state.GetConnectionState();
    const bool mustChangeCredentials =
        state.MustChangeCredentials() || connState == ConnState::FIRST_LOGIN_REQUIRED;
    const bool isConnecting = connState == ConnState::CONNECTING ||
                              connState == ConnState::RECONNECTING ||
                              connState == ConnState::DISCONNECTED;

    if (isConnecting) {
        RenderConnectionScreen(state, width, height, connState, palette);
    } else if (mustChangeCredentials) {
        RenderCredentialChangeScreen(client, state, uiState, width, height, connState, palette);
    } else {
        RenderLoginScreen(client, state, uiState, width, height, connState, palette);
    }
}

void RenderAuthenticatedUi(ChatClient& client,
                           ChatState& state,
                           ClientUiState& uiState,
                           float width,
                           float height,
                           const UiPalette& palette) {
    const std::string currentIdentity = state.CurrentIdentity();

    ImGui::SetCursorPos(ImVec2(0, 42));
    ImGui::BeginChild("##Nodes", ImVec2(width * 0.18f, height - 84), false);
    ImGui::Spacing();
    const std::vector<std::string> activeUsers = state.SnapshotActiveUsers();
    for (const auto& user : activeUsers) {
        const bool isMe = (user == currentIdentity);
        ImGui::TextColored(isMe ? palette.bbsMagenta : palette.bbsLime, " %s", user.c_str());
    }
    ImGui::EndChild();

    ImGui::GetWindowDrawList()->AddLine(
        ImVec2(width * 0.18f, 42),
        ImVec2(width * 0.18f, height - 126),
        ImColor(palette.bbsWhite),
        2.0f);

    ImGui::SetCursorPos(ImVec2(width * 0.18f + 5, 42));
    ImGui::BeginChild("##Feed", ImVec2(width * 0.82f - 5, height - 168), false);
    ImGui::SetWindowFontScale(0.76f);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 1));
    const std::vector<LogEntry> logs = state.SnapshotLogs();
    for (const auto& entry : logs) {
        if (entry.isSystem) {
            ImGui::TextColored(ImVec4(0.7f, 0.7f, 0.7f, 1), "%s", entry.text.c_str());
            continue;
        }

        const bool isMe = (entry.user == currentIdentity);
        if (entry.isAttachment) {
            if (RenderAttachmentLine(entry, isMe, palette))
                HandleAttachmentClick(client, state, uiState, entry.attachment);
            continue;
        }

        const ImColor color = isMe ? ImColor(palette.bbsMagenta) : ImColor(palette.bbsLime);
        ImGui::TextColored(color, "<%s> %s", entry.user.c_str(), entry.text.c_str());
    }
    if (uiState.autoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 20.0f) ImGui::SetScrollHereY(1.0f);
    ImGui::PopStyleVar();
    ImGui::SetWindowFontScale(1.0f);
    ImGui::EndChild();

    ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(0, height - 126), ImVec2(width, height - 84), ImColor(palette.bbsBlue));

    ImGui::SetCursorPos(ImVec2(10, height - 74));
    ImGui::TextColored(palette.bbsMagenta, "%s", currentIdentity.c_str());
    ImGui::SameLine(0, 0);
    ImGui::TextColored(palette.bbsLime, "-->");
    ImGui::SameLine();

    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(0, 0));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0, 0, 0, 0));
    const float attachButtonWidth = 84.0f;
    ImGui::SetNextItemWidth(-attachButtonWidth - 20.0f);
    if (!ImGui::IsAnyItemActive()) ImGui::SetKeyboardFocusHere(0);
    if (ImGui::InputText("##CMD", uiState.input, 512, ImGuiInputTextFlags_EnterReturnsTrue)) {
        if (uiState.input[0] != '\0') {
            ProcessLocalCommand(client, state, currentIdentity, uiState.input);
            std::memset(uiState.input, 0, sizeof(uiState.input));
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Attach", ImVec2(attachButtonWidth, 0))) HandleAttachButton(client, state);
    ImGui::PopStyleColor();
    ImGui::PopStyleVar();

    RenderAttachmentModal(client, state, uiState);
}

void RenderFooterBar(float width, float height) {
    ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(0, height - 42), ImVec2(width, height), ImColor(0.0f, 0.0f, 0.66f, 1.0f));

    std::time_t now = std::time(nullptr);
    char hms[16];
    char yr[8];
    char dt[32];
    std::strftime(hms, sizeof(hms), "%H:%M:%S", std::localtime(&now));
    std::strftime(yr, sizeof(yr), "%Y", std::localtime(&now));
    std::strftime(dt, sizeof(dt), "%a %b %d", std::localtime(&now));

    const std::string fullFooter =
        std::string(hms) + " " + yr + " TZUTC 0200 " + dt + " " + hms + " " + yr + " UTC 0200";
    const float footerTextWidth = ImGui::CalcTextSize(fullFooter.c_str()).x;
    ImGui::SetCursorPos(ImVec2((width - footerTextWidth) * 0.5f, height - 32));

    const ImVec4 cyanPale = ImVec4(0.6f, 1.0f, 1.0f, 1.0f);
    const ImVec4 yellowPale = ImVec4(0.9f, 1.0f, 0.6f, 1.0f);

    ImGui::TextColored(cyanPale, "%s %s TZUTC 0200", hms, yr);
    ImGui::SameLine();
    ImGui::TextColored(yellowPale, " %s ", dt);
    ImGui::SameLine();
    ImGui::TextColored(cyanPale, "%s %s UTC 0200", hms, yr);
}
