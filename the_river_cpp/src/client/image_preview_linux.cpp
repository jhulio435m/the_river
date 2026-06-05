#include "client/image_preview.h"

#include <GL/gl.h>

#ifndef GL_CLAMP_TO_EDGE
#define GL_CLAMP_TO_EDGE 0x812F
#endif

#define STB_IMAGE_IMPLEMENTATION
#include "client/stb_image.h"

bool EnsureImagePreviewTexture(const std::string& path, ImagePreviewTexture& texture, std::string& error) {
    if (texture.textureId != 0 && texture.sourcePath == path) return true;

    ReleaseImagePreviewTexture(texture);

    int width = 0;
    int height = 0;
    int channels = 0;
    stbi_uc* pixels = stbi_load(path.c_str(), &width, &height, &channels, 4);
    if (!pixels) {
        const char* failure = stbi_failure_reason();
        error = failure ? std::string("Could not decode image: ") + failure
                        : "Could not decode the image preview.";
        return false;
    }

    glGenTextures(1, &texture.textureId);
    glBindTexture(GL_TEXTURE_2D, texture.textureId);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
    glPixelStorei(GL_UNPACK_ALIGNMENT, 1);
    glTexImage2D(GL_TEXTURE_2D,
                 0,
                 GL_RGBA,
                 width,
                 height,
                 0,
                 GL_RGBA,
                 GL_UNSIGNED_BYTE,
                 pixels);

    stbi_image_free(pixels);

    texture.width = width;
    texture.height = height;
    texture.sourcePath = path;
    return true;
}

void ReleaseImagePreviewTexture(ImagePreviewTexture& texture) {
    if (texture.textureId != 0) {
        glDeleteTextures(1, &texture.textureId);
        texture.textureId = 0;
    }
    texture.width = 0;
    texture.height = 0;
    texture.sourcePath.clear();
}
