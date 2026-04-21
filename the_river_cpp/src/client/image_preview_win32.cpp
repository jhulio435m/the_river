#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <objidl.h>
#include <gdiplus.h>
#include <GL/GL.h>

#include "client/image_preview.h"

namespace {

bool EnsureGdiplusReady() {
    static bool initialized = false;
    static bool success = false;
    static ULONG_PTR token = 0;
    if (initialized) return success;

    Gdiplus::GdiplusStartupInput startupInput;
    success = Gdiplus::GdiplusStartup(&token, &startupInput, nullptr) == Gdiplus::Ok;
    initialized = true;
    return success;
}

std::wstring ToWide(const std::string& value) {
    return std::wstring(value.begin(), value.end());
}

}  // namespace

bool EnsureImagePreviewTexture(const std::string& path, ImagePreviewTexture& texture, std::string& error) {
    if (texture.textureId != 0 && texture.sourcePath == path) return true;
    if (!EnsureGdiplusReady()) {
        error = "No se pudo inicializar GDI+ para la vista previa.";
        return false;
    }

    ReleaseImagePreviewTexture(texture);
    Gdiplus::Bitmap bitmap(ToWide(path).c_str());
    if (bitmap.GetLastStatus() != Gdiplus::Ok) {
        error = "No se pudo decodificar la imagen para la vista previa.";
        return false;
    }

    const UINT width = bitmap.GetWidth();
    const UINT height = bitmap.GetHeight();
    Gdiplus::Rect rect(0, 0, static_cast<INT>(width), static_cast<INT>(height));
    Gdiplus::BitmapData bitmapData{};
    if (bitmap.LockBits(&rect, Gdiplus::ImageLockModeRead, PixelFormat32bppARGB, &bitmapData) != Gdiplus::Ok) {
        error = "No se pudo leer la imagen para la vista previa.";
        return false;
    }

    glGenTextures(1, &texture.textureId);
    glBindTexture(GL_TEXTURE_2D, texture.textureId);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP);
    glPixelStorei(GL_UNPACK_ALIGNMENT, 4);
    glTexImage2D(GL_TEXTURE_2D,
                 0,
                 GL_RGBA,
                 static_cast<GLsizei>(width),
                 static_cast<GLsizei>(height),
                 0,
                 GL_BGRA_EXT,
                 GL_UNSIGNED_BYTE,
                 bitmapData.Scan0);
    bitmap.UnlockBits(&bitmapData);

    texture.width = static_cast<int>(width);
    texture.height = static_cast<int>(height);
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
