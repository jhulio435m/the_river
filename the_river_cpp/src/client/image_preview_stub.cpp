#include "client/image_preview.h"

bool EnsureImagePreviewTexture(const std::string& path, ImagePreviewTexture& texture, std::string& error) {
    (void)path;
    (void)texture;
    error = "La vista previa embebida de imagen solo esta implementada en Windows por ahora.";
    return false;
}

void ReleaseImagePreviewTexture(ImagePreviewTexture& texture) {
    texture.textureId = 0;
    texture.width = 0;
    texture.height = 0;
    texture.sourcePath.clear();
}
