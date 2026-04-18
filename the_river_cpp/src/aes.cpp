#include "../include/aes.h"
#include <string>
#include <vector>
#include <cstring>
#include <random>
#include <stdint.h>

// ============================================================
//  AES-128-CBC  —  Implementacion standalone (sin OpenSSL)
//  Modo: CBC con PKCS7 padding
//  IV:  16 bytes aleatorios generados en cada Encrypt,
//       antepuestos al ciphertext → base64(IV || CT)
// ============================================================

typedef uint8_t byte;

// ---------- S-Box y S-Box inversa ----------
static const byte sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const byte rsbox[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const byte Rcon[10] = {
    0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36
};

// ---------- Base64 ----------
static const std::string B64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string b64_encode(const byte* buf, size_t len) {
    std::string ret;
    size_t i = 0;
    byte c3[3], c4[4];
    while (len--) {
        c3[i++] = *buf++;
        if (i == 3) {
            c4[0] = (c3[0] & 0xfc) >> 2;
            c4[1] = ((c3[0] & 0x03) << 4) + ((c3[1] & 0xf0) >> 4);
            c4[2] = ((c3[1] & 0x0f) << 2) + ((c3[2] & 0xc0) >> 6);
            c4[3] =  c3[2] & 0x3f;
            for (int k = 0; k < 4; k++) ret += B64_CHARS[c4[k]];
            i = 0;
        }
    }
    if (i) {
        for (size_t j = i; j < 3; j++) c3[j] = 0;
        c4[0] = (c3[0] & 0xfc) >> 2;
        c4[1] = ((c3[0] & 0x03) << 4) + ((c3[1] & 0xf0) >> 4);
        c4[2] = ((c3[1] & 0x0f) << 2) + ((c3[2] & 0xc0) >> 6);
        for (size_t j = 0; j < i + 1; j++) ret += B64_CHARS[c4[j]];
        while (i++ < 3) ret += '=';
    }
    return ret;
}

static std::vector<byte> b64_decode(const std::string& s) {
    std::vector<byte> ret;
    int i = 0, in_ = 0;
    byte c4[4], c3[3];
    size_t in_len = s.size();
    while (in_len-- && s[in_] != '=' &&
           (isalnum(s[in_]) || s[in_] == '+' || s[in_] == '/')) {
        c4[i++] = s[in_++];
        if (i == 4) {
            for (int k = 0; k < 4; k++) c4[k] = (byte)B64_CHARS.find(c4[k]);
            c3[0] = (c4[0] << 2)        + ((c4[1] & 0x30) >> 4);
            c3[1] = ((c4[1] & 0xf) << 4) + ((c4[2] & 0x3c) >> 2);
            c3[2] = ((c4[2] & 0x3) << 6) + c4[3];
            for (int k = 0; k < 3; k++) ret.push_back(c3[k]);
            i = 0;
        }
    }
    if (i) {
        for (int j = i; j < 4; j++) c4[j] = 0;
        for (int j = 0; j < 4; j++) c4[j] = (byte)B64_CHARS.find(c4[j]);
        c3[0] = (c4[0] << 2)        + ((c4[1] & 0x30) >> 4);
        c3[1] = ((c4[1] & 0xf) << 4) + ((c4[2] & 0x3c) >> 2);
        for (int j = 0; j < i - 1; j++) ret.push_back(c3[j]);
    }
    return ret;
}

// ---------- GF(2^8) multiplicacion ----------
static byte gmul(byte a, byte b) {
    byte p = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) p ^= a;
        bool hi = (a & 0x80) != 0;
        a <<= 1;
        if (hi) a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

// ---------- Key Expansion (AES-128: 10 rondas, 176 bytes) ----------
static void KeyExpansion(const byte* key, byte* w) {
    memcpy(w, key, 16);
    for (int i = 4; i < 44; i++) {
        byte temp[4];
        memcpy(temp, w + (i - 1) * 4, 4);
        if (i % 4 == 0) {
            byte t = temp[0];
            temp[0] = sbox[temp[1]];
            temp[1] = sbox[temp[2]];
            temp[2] = sbox[temp[3]];
            temp[3] = sbox[t];
            temp[0] ^= Rcon[i / 4 - 1];
        }
        for (int j = 0; j < 4; j++)
            w[i * 4 + j] = w[(i - 4) * 4 + j] ^ temp[j];
    }
}

// ---------- Operaciones sobre el estado (4x4, column-major) ----------
static void AddRoundKey(byte s[4][4], const byte* rk) {
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            s[r][c] ^= rk[c * 4 + r];
}
static void SubBytes(byte s[4][4]) {
    for (int r = 0; r < 4; r++) for (int c = 0; c < 4; c++) s[r][c] = sbox[s[r][c]];
}
static void InvSubBytes(byte s[4][4]) {
    for (int r = 0; r < 4; r++) for (int c = 0; c < 4; c++) s[r][c] = rsbox[s[r][c]];
}
static void ShiftRows(byte s[4][4]) {
    byte t;
    t=s[1][0]; s[1][0]=s[1][1]; s[1][1]=s[1][2]; s[1][2]=s[1][3]; s[1][3]=t;
    t=s[2][0]; s[2][0]=s[2][2]; s[2][2]=t; t=s[2][1]; s[2][1]=s[2][3]; s[2][3]=t;
    t=s[3][3]; s[3][3]=s[3][2]; s[3][2]=s[3][1]; s[3][1]=s[3][0]; s[3][0]=t;
}
static void InvShiftRows(byte s[4][4]) {
    byte t;
    t=s[1][3]; s[1][3]=s[1][2]; s[1][2]=s[1][1]; s[1][1]=s[1][0]; s[1][0]=t;
    t=s[2][0]; s[2][0]=s[2][2]; s[2][2]=t; t=s[2][1]; s[2][1]=s[2][3]; s[2][3]=t;
    t=s[3][0]; s[3][0]=s[3][1]; s[3][1]=s[3][2]; s[3][2]=s[3][3]; s[3][3]=t;
}
static void MixColumns(byte s[4][4]) {
    for (int c = 0; c < 4; c++) {
        byte a=s[0][c],b=s[1][c],cc=s[2][c],d=s[3][c];
        s[0][c]=gmul(a,2)^gmul(b,3)^cc^d;
        s[1][c]=a^gmul(b,2)^gmul(cc,3)^d;
        s[2][c]=a^b^gmul(cc,2)^gmul(d,3);
        s[3][c]=gmul(a,3)^b^cc^gmul(d,2);
    }
}
static void InvMixColumns(byte s[4][4]) {
    for (int c = 0; c < 4; c++) {
        byte a=s[0][c],b=s[1][c],cc=s[2][c],d=s[3][c];
        s[0][c]=gmul(a,0x0e)^gmul(b,0x0b)^gmul(cc,0x0d)^gmul(d,0x09);
        s[1][c]=gmul(a,0x09)^gmul(b,0x0e)^gmul(cc,0x0b)^gmul(d,0x0d);
        s[2][c]=gmul(a,0x0d)^gmul(b,0x09)^gmul(cc,0x0e)^gmul(d,0x0b);
        s[3][c]=gmul(a,0x0b)^gmul(b,0x0d)^gmul(cc,0x09)^gmul(d,0x0e);
    }
}

// ---------- Cifrado/descifrado de un bloque (16 bytes) ----------
static void AES_Encrypt_Block(const byte* in, byte* out, const byte* w) {
    byte s[4][4];
    for (int c=0;c<4;c++) for (int r=0;r<4;r++) s[r][c]=in[c*4+r];
    AddRoundKey(s, w);
    for (int round = 1; round <= 10; round++) {
        SubBytes(s); ShiftRows(s);
        if (round < 10) MixColumns(s);
        AddRoundKey(s, w + round * 16);
    }
    for (int c=0;c<4;c++) for (int r=0;r<4;r++) out[c*4+r]=s[r][c];
}
static void AES_Decrypt_Block(const byte* in, byte* out, const byte* w) {
    byte s[4][4];
    for (int c=0;c<4;c++) for (int r=0;r<4;r++) s[r][c]=in[c*4+r];
    AddRoundKey(s, w + 160);
    for (int round = 9; round >= 0; round--) {
        InvShiftRows(s); InvSubBytes(s);
        AddRoundKey(s, w + round * 16);
        if (round > 0) InvMixColumns(s);
    }
    for (int c=0;c<4;c++) for (int r=0;r<4;r++) out[c*4+r]=s[r][c];
}

// ---------- Helpers ----------
static void PrepareKey16(const std::string& key, byte* out) {
    memset(out, 0, 16);
    for (size_t i = 0; i < 16 && i < key.size(); i++) out[i] = (byte)key[i];
}
static std::vector<byte> GenRandomIV() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dis(0, 255);
    std::vector<byte> iv(16);
    for (auto& b : iv) b = (byte)dis(gen);
    return iv;
}

// ============================================================
//  API publica
// ============================================================
std::string AESHelper::Encrypt(const std::string& plainText,
                               const std::string& key,
                               const std::string& /*iv*/) {
    byte aesKey[16]; PrepareKey16(key, aesKey);
    byte w[176];     KeyExpansion(aesKey, w);

    // PKCS7 padding
    std::string padded = plainText;
    int pad = 16 - (int)(padded.size() % 16);
    for (int i = 0; i < pad; i++) padded += (char)pad;

    // IV aleatorio
    std::vector<byte> iv = GenRandomIV();

    // CBC encrypt
    std::vector<byte> ct(padded.size());
    byte prev[16]; memcpy(prev, iv.data(), 16);
    for (size_t blk = 0; blk < padded.size() / 16; blk++) {
        byte in[16], out[16];
        for (int i = 0; i < 16; i++) in[i] = (byte)padded[blk*16+i] ^ prev[i];
        AES_Encrypt_Block(in, out, w);
        memcpy(prev, out, 16);
        memcpy(ct.data() + blk*16, out, 16);
    }

    // Anteponer IV al ciphertext
    std::vector<byte> result(iv.begin(), iv.end());
    result.insert(result.end(), ct.begin(), ct.end());
    return b64_encode(result.data(), result.size());
}

std::string AESHelper::Decrypt(const std::string& cipherText,
                               const std::string& key,
                               const std::string& /*iv*/) {
    std::vector<byte> decoded = b64_decode(cipherText);
    if (decoded.size() < 32 || (decoded.size() - 16) % 16 != 0)
        return "[DECRYPT_ERR]";

    byte iv[16]; memcpy(iv, decoded.data(), 16);
    const byte* ct = decoded.data() + 16;
    size_t ctLen = decoded.size() - 16;

    byte aesKey[16]; PrepareKey16(key, aesKey);
    byte w[176];     KeyExpansion(aesKey, w);

    // CBC decrypt
    std::string decrypted(ctLen, 0);
    byte prev[16]; memcpy(prev, iv, 16);
    for (size_t blk = 0; blk < ctLen / 16; blk++) {
        byte out[16];
        AES_Decrypt_Block(ct + blk*16, out, w);
        for (int i = 0; i < 16; i++)
            decrypted[blk*16+i] = (char)(out[i] ^ prev[i]);
        memcpy(prev, ct + blk*16, 16);
    }

    // Quitar PKCS7 padding
    if (!decrypted.empty()) {
        int p = (uint8_t)decrypted.back();
        if (p > 0 && p <= 16 && (int)decrypted.size() >= p) {
            bool ok = true;
            for (int i = 0; i < p; i++)
                if ((uint8_t)decrypted[decrypted.size()-1-i] != p) { ok=false; break; }
            if (ok) decrypted.resize(decrypted.size() - p);
        }
    }
    return decrypted;
}
