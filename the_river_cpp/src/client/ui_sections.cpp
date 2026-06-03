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

constexpr float kCompactLayoutWidth = 720.0f;

bool IsCompactLayout(float width) {
    return width < kCompactLayoutWidth;
}

float HeaderHeightForWidth(float width) {
    return IsCompactLayout(width) ? 56.0f : 42.0f;
}

float FooterHeightForWidth(float width) {
    (void)width;
    return 42.0f;
}

float ClampPanelWidth(float width, float desiredWidth) {
    const float maxWidth = width - 32.0f;
    if (maxWidth < 280.0f) return width;
    return desiredWidth < maxWidth ? desiredWidth : maxWidth;
}

int CommandInputCallback(ImGuiInputTextCallbackData* data) {
#ifndef _WIN32
    const bool pasteRequested =
        (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_V, false)) ||
        (ImGui::GetIO().KeyShift && ImGui::IsKeyPressed(ImGuiKey_Insert, false));
    if (pasteRequested) {
        const char* clipboard = ImGui::GetClipboardText();
        if (clipboard && clipboard[0] != '\0') data->InsertChars(data->CursorPos, clipboard);
    }
#else
    (void)data;
#endif
    return 0;
}

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
    const bool compactLayout = IsCompactLayout(width);
    ImGui::SetCursorPos(ImVec2(0, 0));
    ImGui::BeginChild("##IntroAnim", ImVec2(width, height), false,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoInputs | ImGuiWindowFlags_NoBackground);

    const int yStep = compactLayout ? 32 : 24;
    const int xStep = compactLayout ? 44 : 32;
    const float noiseThreshold = compactLayout ? 0.48f : 0.35f;
    for (int y = 0; y < static_cast<int>(height); y += yStep) {
        for (int x = 0; x < static_cast<int>(width); x += xStep) {
            const float noise = std::sin(x * 0.05f + t * 2.5f) * std::cos(y * 0.05f - t * 1.8f);
            if (noise > noiseThreshold) {
                ImGui::SetCursorPos(ImVec2(static_cast<float>(x), static_cast<float>(y)));
                const ImVec4 blockCol =
                    (std::sin(t * 12.0f + x) > 0) ? ImVec4(0.8f, 0.0f, 0.0f, 0.35f) : ImVec4(0.0f, 0.8f, 0.4f, 0.35f);
                ImGui::TextColored(blockCol, "█");
            }
        }
    }
    ImGui::EndChild();

    const float panelWidth = ClampPanelWidth(width, 500.0f);
    ImGui::SetCursorPos(ImVec2((width - panelWidth) * 0.5f, height * 0.5f - 70.0f));
    ImGui::BeginChild("##ConnectingPanel", ImVec2(panelWidth, 160), true);
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
    const bool compactLayout = IsCompactLayout(width);
    const float panelWidth = ClampPanelWidth(width, 500.0f);
    const float buttonHeight = compactLayout ? 48.0f : 42.0f;

    ImGui::SetCursorPos(ImVec2((width - panelWidth) * 0.5f, height * 0.5f - 180.0f));
    ImGui::BeginChild("##FirstLoginPanel", ImVec2(panelWidth, 360), true);
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
    if (ImGui::Button("ACTUALIZAR CREDENCIALES", ImVec2(-1, buttonHeight))) submitCredentialChange = true;
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
    const bool compactLayout = IsCompactLayout(width);
    const float panelWidth = ClampPanelWidth(width, 440.0f);
    const float buttonHeight = compactLayout ? 48.0f : 40.0f;

    ImGui::SetCursorPos(ImVec2((width - panelWidth) * 0.5f, height * 0.5f - 150.0f));
    ImGui::BeginChild("##AccessPanel", ImVec2(panelWidth, 300), true);
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
    if (ImGui::Button("ESTABLISH UPLINK", ImVec2(-1, buttonHeight))) submitLogin = true;
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

bool RenderCopyableLine(const std::string& id, const std::string& text, const ImVec4& color) {
    const ImVec4 hoverColor(color.x * 0.18f, color.y * 0.18f, color.z * 0.18f, 0.60f);
    const ImVec4 activeColor(color.x * 0.28f, color.y * 0.28f, color.z * 0.28f, 0.85f);
    const std::string label = text + "##" + id;

    ImGui::PushStyleColor(ImGuiCol_Text, color);
    ImGui::PushStyleColor(ImGuiCol_Header, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_HeaderHovered, hoverColor);
    ImGui::PushStyleColor(ImGuiCol_HeaderActive, activeColor);
    const bool clicked = ImGui::Selectable(label.c_str(), false, ImGuiSelectableFlags_AllowDoubleClick);
    ImGui::PopStyleColor(4);

    if (clicked) ImGui::SetClipboardText(text.c_str());
    return clicked;
}

void HandleAttachButton(ClientUiState& uiState) {
    uiState.attachPickerOpen = true;
    uiState.attachPickerError.clear();
}

void ResetAttachPicker(ClientUiState& uiState) {
    uiState.attachPickerOpen = false;
    uiState.attachPickerError.clear();
    std::memset(uiState.attachPath, 0, sizeof(uiState.attachPath));
}

void RenderAttachPickerModal(ChatClient& client, ChatState& state, ClientUiState& uiState) {
    if (!uiState.attachPickerOpen) return;

    if (!ImGui::IsPopupOpen("##AttachPicker")) ImGui::OpenPopup("##AttachPicker");
    bool keepOpen = true;
    if (ImGui::BeginPopupModal("##AttachPicker", &keepOpen, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text("Adjuntar archivo local");
        ImGui::Separator();
        ImGui::TextWrapped("En Linux este flujo evita depender por completo del dialogo externo y reduce fallos de sesion en Debian.");
        ImGui::Spacing();
        ImGui::SetNextItemWidth(520.0f);
        const bool submitPath = ImGui::InputText(
            "##ATTACH_PATH",
            uiState.attachPath,
            IM_ARRAYSIZE(uiState.attachPath),
            ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::SameLine();
        if (ImGui::Button("Browse...", ImVec2(110, 0))) {
            AttachmentDraft draft;
            std::string pickerError;
            if (PickAttachmentFile(draft, pickerError)) {
                std::strncpy(uiState.attachPath, draft.localPath.c_str(), sizeof(uiState.attachPath) - 1);
                uiState.attachPath[sizeof(uiState.attachPath) - 1] = '\0';
                uiState.attachPickerError.clear();
            } else if (!pickerError.empty()) {
                uiState.attachPickerError = pickerError;
            }
        }

        if (!uiState.attachPickerError.empty()) {
            ImGui::Spacing();
            ImGui::TextWrapped("%s", uiState.attachPickerError.c_str());
        }

        ImGui::Spacing();
        bool shouldAttach = submitPath;
        if (ImGui::Button("Attach", ImVec2(110, 0))) shouldAttach = true;
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(110, 0))) keepOpen = false;

        if (shouldAttach) {
            const std::string attachPath = TrimCopy(uiState.attachPath);
            if (attachPath.empty()) {
                uiState.attachPickerError = "Debes indicar una ruta de archivo.";
            } else {
                AttachmentDraft draft;
                std::string buildError;
                if (!BuildAttachmentDraftFromPath(attachPath, draft, buildError)) {
                    uiState.attachPickerError = buildError;
                } else {
                    const std::string currentIdentity = state.CurrentIdentity();
                    if (currentIdentity.empty()) {
                        uiState.attachPickerError = "No hay identidad autenticada para adjuntar archivos.";
                    } else if (!client.SendAttachment(currentIdentity, draft)) {
                        uiState.attachPickerError = state.LastError().empty()
                            ? "No se pudo enviar el adjunto seleccionado."
                            : state.LastError();
                    } else {
                        keepOpen = false;
                    }
                }
            }
        }

        ImGui::EndPopup();
    }

    if (!keepOpen) ResetAttachPicker(uiState);
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
    (void)client;
    uiState.attachmentModalOpen = true;
    uiState.attachmentModalOwner = attachment.ownerUser;
    uiState.attachmentModalId = attachment.id;
    uiState.attachmentModalError.clear();
    uiState.attachmentModalLoading = false;
    ReleaseImagePreviewTexture(uiState.attachmentPreviewTexture);
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

        const bool isRemoteAttachment = attachment.localPath.empty() && attachment.ownerUser != state.CurrentIdentity();
        uiState.attachmentModalLoading =
            isRemoteAttachment && attachment.state == AttachmentTransferState::Requested;
        if (uiState.attachmentModalLoading) {
            ImGui::TextColored(ImVec4(0.9f, 0.9f, 0.4f, 1.0f), "Receiving attachment...");
        } else if (!uiState.attachmentModalError.empty()) {
            ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.32f, 1.0f), "%s", uiState.attachmentModalError.c_str());
        } else if (isRemoteAttachment) {
            ImGui::TextWrapped("Attachment metadata received. Download only when you choose Preview or Save As.");
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
        if (isRemoteAttachment && attachment.kind != AttachmentKind::File) {
            if (ImGui::Button("Preview", ImVec2(110, 0))) {
                const std::string previewPath = BuildAttachmentCachePath(attachment.id, attachment.displayName);
                if (!client.RequestAttachment(attachment, previewPath, "preview"))
                    uiState.attachmentModalError = state.LastError().empty()
                        ? "No se pudo solicitar la previsualizacion."
                        : state.LastError();
            }
            ImGui::SameLine();
        }
        if (attachment.kind != AttachmentKind::File && !attachment.localPath.empty()) {
            if (ImGui::Button("Open", ImVec2(110, 0))) {
                if (!OpenPathWithShell(attachment.localPath))
                    uiState.attachmentModalError =
                        attachment.kind == AttachmentKind::Image
                            ? "No se pudo abrir la imagen."
                            : "No se pudo abrir el video.";
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
        } else if (isRemoteAttachment) {
            if (ImGui::Button("Save As...", ImVec2(110, 0))) SaveAttachmentAs(client, state, attachment);
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
    const bool compactLayout = IsCompactLayout(width);
    const float headerHeight = HeaderHeightForWidth(width);
    ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(0, 0), ImVec2(width, headerHeight), ImColor(palette.bbsBlue));
    ImGui::SetCursorPos(ImVec2(10, 6));
    ImGui::Text("Active Users %d <SECURE UPLINK>", state.ActiveUserCount());

    if (compactLayout) {
        ImGui::SetCursorPos(ImVec2(10, 28));
        ImGui::TextColored(ImVec4(1, 1, 0, 1), "[%s]", UiStatusLabel(state.GetConnectionState()));
        if (width > 360.0f) {
            ImGui::SetCursorPos(ImVec2(width - 170.0f, 28));
            ImGui::TextDisabled("termux/mobile layout");
        }
        return;
    }

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
    const bool compactLayout = IsCompactLayout(width);
    const float headerHeight = HeaderHeightForWidth(width);
    const float footerHeight = FooterHeightForWidth(width);
    const float inputBandHeight = compactLayout ? 96.0f : 84.0f;
    const float inputTop = height - footerHeight - inputBandHeight;
    float feedTop = headerHeight;
    const std::vector<std::string> activeUsers = state.SnapshotActiveUsers();

    if (compactLayout) {
        ImGui::SetCursorPos(ImVec2(8, headerHeight + 6));
        if (ImGui::Button(uiState.usersPanelOpen ? "Hide Users" : "Show Users", ImVec2(120, 34))) {
            uiState.usersPanelOpen = !uiState.usersPanelOpen;
        }
        ImGui::SameLine();
        ImGui::TextColored(UiStatusColor(state.GetConnectionState()), "[%s]", UiStatusLabel(state.GetConnectionState()));
        feedTop += 46.0f;

        if (uiState.usersPanelOpen) {
            ImGui::SetCursorPos(ImVec2(8, feedTop));
            ImGui::BeginChild("##CompactUsers", ImVec2(width - 16.0f, 84.0f), true);
            for (std::size_t index = 0; index < activeUsers.size(); ++index) {
                const std::string& user = activeUsers[index];
                const bool isMe = (user == currentIdentity);
                ImGui::TextColored(isMe ? palette.bbsMagenta : palette.bbsLime, "%s", user.c_str());
                if (index + 1 < activeUsers.size()) ImGui::SameLine();
            }
            ImGui::EndChild();
            feedTop += 92.0f;
        }
    }

    if (!compactLayout) {
        ImGui::SetCursorPos(ImVec2(0, headerHeight));
        ImGui::BeginChild("##Nodes", ImVec2(width * 0.18f, inputTop - headerHeight), false);
        ImGui::Spacing();
        for (const auto& user : activeUsers) {
            const bool isMe = (user == currentIdentity);
            ImGui::TextColored(isMe ? palette.bbsMagenta : palette.bbsLime, " %s", user.c_str());
        }
        ImGui::EndChild();

        ImGui::GetWindowDrawList()->AddLine(
            ImVec2(width * 0.18f, headerHeight),
            ImVec2(width * 0.18f, inputTop),
            ImColor(palette.bbsWhite),
            2.0f);

        ImGui::SetCursorPos(ImVec2(width * 0.18f + 5, headerHeight));
        ImGui::BeginChild("##Feed", ImVec2(width * 0.82f - 5, inputTop - headerHeight), false);
    } else {
        ImGui::SetCursorPos(ImVec2(8, feedTop));
        ImGui::BeginChild("##Feed", ImVec2(width - 16.0f, inputTop - feedTop), false);
    }
    ImGui::SetWindowFontScale(0.76f);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 1));
    const std::vector<LogEntry> logs = state.SnapshotLogs();
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(logs.size()));
    while (clipper.Step()) {
        for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index) {
            const LogEntry& entry = logs[index];
            const std::string lineId = "copy_line_" + std::to_string(index);
            if (entry.isSystem) {
                RenderCopyableLine(lineId, entry.text, ImVec4(0.7f, 0.7f, 0.7f, 1.0f));
                continue;
            }

            const bool isMe = (entry.user == currentIdentity);
            const ImVec4 lineColor = isMe ? palette.bbsMagenta : palette.bbsLime;
            if (entry.isAttachment) {
                const std::string attachmentLine =
                    "<" + entry.user + "> [" + AttachmentKindToLabel(entry.attachment.kind) + "] " +
                    entry.attachment.displayName + " (" + FormatAttachmentSize(entry.attachment.sizeBytes) + ")";
                const bool clicked = RenderCopyableLine(lineId, attachmentLine, lineColor);
                if (clicked && (compactLayout || ImGui::IsMouseDoubleClicked(0)))
                    HandleAttachmentClick(client, state, uiState, entry.attachment);
                continue;
            }

            RenderCopyableLine(lineId, "<" + entry.user + "> " + entry.text, lineColor);
        }
    }
    if (uiState.autoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 20.0f) ImGui::SetScrollHereY(1.0f);
    ImGui::PopStyleVar();
    ImGui::SetWindowFontScale(1.0f);
    ImGui::EndChild();

    ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(0, inputTop), ImVec2(width, height - footerHeight), ImColor(palette.bbsBlue));

    ImGui::SetCursorPos(ImVec2(10, inputTop + 6));
    ImGui::TextColored(palette.bbsMagenta, "%s", currentIdentity.c_str());
    ImGui::SameLine(0, 0);
    ImGui::TextColored(palette.bbsLime, "-->");
    ImGui::SameLine();

    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, compactLayout ? ImVec2(4, 8) : ImVec2(0, 0));
    ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0, 0, 0, 0));
    const float attachButtonWidth = compactLayout ? 110.0f : 84.0f;
    ImGui::SetCursorPos(ImVec2(10, inputTop + (compactLayout ? 30.0f : 22.0f)));
    ImGui::SetNextItemWidth(-attachButtonWidth - 20.0f);
    if (!ImGui::IsAnyItemActive()) ImGui::SetKeyboardFocusHere(0);
    if (ImGui::InputText(
            "##CMD",
            uiState.input,
            512,
            ImGuiInputTextFlags_EnterReturnsTrue | ImGuiInputTextFlags_CallbackAlways,
            CommandInputCallback)) {
        if (uiState.input[0] != '\0') {
            ProcessLocalCommand(client, state, currentIdentity, uiState.input);
            std::memset(uiState.input, 0, sizeof(uiState.input));
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Attach", ImVec2(attachButtonWidth, 0))) HandleAttachButton(uiState);
    ImGui::PopStyleColor();
    ImGui::PopStyleVar();

    RenderAttachPickerModal(client, state, uiState);
    RenderAttachmentModal(client, state, uiState);
}

void RenderFooterBar(float width, float height) {
    const bool compactLayout = IsCompactLayout(width);
    const float footerHeight = FooterHeightForWidth(width);
    ImGui::GetWindowDrawList()->AddRectFilled(ImVec2(0, height - footerHeight), ImVec2(width, height), ImColor(0.0f, 0.0f, 0.66f, 1.0f));

    std::time_t now = std::time(nullptr);
    char hms[16];
    char yr[8];
    char dt[32];
    std::strftime(hms, sizeof(hms), "%H:%M:%S", std::localtime(&now));
    std::strftime(yr, sizeof(yr), "%Y", std::localtime(&now));
    std::strftime(dt, sizeof(dt), "%a %b %d", std::localtime(&now));

    const std::string fullFooter =
        compactLayout
            ? std::string(dt) + " " + hms
            : std::string(hms) + " " + yr + " TZUTC 0200 " + dt + " " + hms + " " + yr + " UTC 0200";
    const float footerTextWidth = ImGui::CalcTextSize(fullFooter.c_str()).x;
    ImGui::SetCursorPos(ImVec2((width - footerTextWidth) * 0.5f, height - 32));

    const ImVec4 cyanPale = ImVec4(0.6f, 1.0f, 1.0f, 1.0f);
    const ImVec4 yellowPale = ImVec4(0.9f, 1.0f, 0.6f, 1.0f);

    if (compactLayout) {
        ImGui::TextColored(yellowPale, "%s", dt);
        ImGui::SameLine();
        ImGui::TextColored(cyanPale, " %s", hms);
    } else {
        ImGui::TextColored(cyanPale, "%s %s TZUTC 0200", hms, yr);
        ImGui::SameLine();
        ImGui::TextColored(yellowPale, " %s ", dt);
        ImGui::SameLine();
        ImGui::TextColored(cyanPale, "%s %s UTC 0200", hms, yr);
    }
}
