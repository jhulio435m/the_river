#pragma once

#include <string>

struct ImagePreviewTexture {
    unsigned int textureId = 0;
    int width = 0;
    int height = 0;
    std::string sourcePath;
};

bool EnsureImagePreviewTexture(const std::string& path, ImagePreviewTexture& texture, std::string& error);
void ReleaseImagePreviewTexture(ImagePreviewTexture& texture);
