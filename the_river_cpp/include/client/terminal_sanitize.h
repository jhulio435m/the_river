#pragma once

// Makes network-supplied text safe to print on a terminal (admin console):
// every C0 control byte (< 0x20), DEL (0x7f) and C1 control (U+0080..U+009F)
// becomes '?', and every byte that is not part of a valid UTF-8 sequence
// (overlong forms, surrogates, > U+10FFFF, truncated sequences) becomes '?'.
// No escape sequence (CSI, OSC 52 clipboard writes, title changes, fake
// prompts via \r) can survive. Header-only so the console and tests share it.

#include <cstddef>
#include <string>

namespace river {

inline std::string SanitizeForTerminal(const std::string& input) {
    std::string out;
    out.reserve(input.size());
    const std::size_t n = input.size();
    std::size_t i = 0;
    while (i < n) {
        const unsigned char c = static_cast<unsigned char>(input[i]);
        if (c < 0x80) {
            out.push_back((c < 0x20 || c == 0x7f) ? '?' : static_cast<char>(c));
            ++i;
            continue;
        }
        std::size_t len = 0;
        unsigned int cp = 0;
        if (c >= 0xC2 && c <= 0xDF) {
            len = 2;
            cp = c & 0x1F;
        } else if (c >= 0xE0 && c <= 0xEF) {
            len = 3;
            cp = c & 0x0F;
        } else if (c >= 0xF0 && c <= 0xF4) {
            len = 4;
            cp = c & 0x07;
        }
        bool valid = len > 0 && i + len <= n;
        for (std::size_t k = 1; valid && k < len; ++k) {
            const unsigned char cc = static_cast<unsigned char>(input[i + k]);
            if ((cc & 0xC0) != 0x80) valid = false;
            else cp = (cp << 6) | (cc & 0x3F);
        }
        if (valid) {
            if ((len == 3 && cp < 0x800) || (len == 4 && (cp < 0x10000 || cp > 0x10FFFF)) ||
                (cp >= 0xD800 && cp <= 0xDFFF)) {
                valid = false;
            }
        }
        if (!valid) {
            out.push_back('?');
            ++i;
            continue;
        }
        if (cp >= 0x80 && cp <= 0x9F) {
            out.push_back('?');  // C1 control (e.g. U+009B = CSI)
        } else {
            out.append(input, i, len);
        }
        i += len;
    }
    return out;
}

}  // namespace river
