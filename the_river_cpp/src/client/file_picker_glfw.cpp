#include "client/file_picker.h"

bool PickAttachmentFile(AttachmentDraft& draft, std::string& error) {
    (void)draft;
    error = "El selector de adjuntos solo esta implementado en Windows por ahora.";
    return false;
}

bool PickAttachmentSavePath(const AttachmentPayload& attachment, std::string& savePath, std::string& error) {
    (void)attachment;
    (void)savePath;
    error = "Guardar adjuntos desde la UI solo esta implementado en Windows por ahora.";
    return false;
}

bool OpenPathWithShell(const std::string& path) {
    (void)path;
    return false;
}
