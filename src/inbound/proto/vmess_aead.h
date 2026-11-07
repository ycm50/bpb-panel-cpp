#pragma once
// VMess cryptographic primitives.
//
// Everything here is a port of Xray's proxy/vmess/aead plus the pieces of
// common/crypto the VMess body framing needs. The KDF is the one subtle part:
// Go builds a nested HMAC whose outer and inner hashes are the SAME object
// (hash2{previous}), and its Sum() rewrites opad then finalises through the
// previous level. That is not the textbook "HMAC(salt, path||key)" chain, so it
// is reproduced structurally below and pinned by four reference vectors (see
// tmpscripts/kdf_check.cpp, which matches the Go oracle 4/4).
#include <openssl/evp.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace bpb::proxy::vmess {

inline const char* kdf_salt = "VMess AEAD KDF";

inline std::string to_bytes(const unsigned char* p, std::size_t n) {
    return std::string(reinterpret_cast<const char*>(p), n);
}

inline std::string hex(const std::string& in) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(in.size() * 2);
    for (unsigned char c : in) {
        out += digits[c >> 4];
        out += digits[c & 0x0F];
    }
    return out;
}

inline std::string sha256(const std::string& in) {
    unsigned char out[32];
    unsigned int len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return std::string(32, '\0');
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, in.data(), in.size());
    EVP_DigestFinal_ex(ctx, out, &len);
    EVP_MD_CTX_free(ctx);
    return to_bytes(out, sizeof(out));
}

inline std::string md5(const std::string& in) {
    unsigned char out[16];
    unsigned int len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return std::string(16, '\0');
    EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(ctx, in.data(), in.size());
    EVP_DigestFinal_ex(ctx, out, &len);
    EVP_MD_CTX_free(ctx);
    return to_bytes(out, sizeof(out));
}

inline std::uint32_t fnv1a32(const std::string& in) {
    std::uint32_t h = 2166136261u;
    for (unsigned char c : in) {
        h ^= c;
        h *= 16777619u;
    }
    return h;
}

inline std::uint32_t crc32_ieee(const std::string& in) {
    static std::uint32_t table[256];
    static bool ready = false;
    if (!ready) {
        for (std::uint32_t i = 0; i < 256; ++i) {
            std::uint32_t c = i;
            for (int k = 0; k < 8; ++k) c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            table[i] = c;
        }
        ready = true;
    }
    std::uint32_t c = 0xFFFFFFFFu;
    for (unsigned char b : in) c = table[(c ^ b) & 0xFF] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

inline std::string be16(std::uint16_t v) {
    std::string out(2, '\0');
    out[0] = static_cast<char>((v >> 8) & 0xFF);
    out[1] = static_cast<char>(v & 0xFF);
    return out;
}

inline std::uint16_t read_be16(const char* p) {
    return static_cast<std::uint16_t>((static_cast<unsigned char>(p[0]) << 8) |
                                      static_cast<unsigned char>(p[1]));
}

inline std::uint32_t read_be32(const char* p) {
    return (static_cast<std::uint32_t>(static_cast<unsigned char>(p[0])) << 24) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(p[1])) << 16) |
           (static_cast<std::uint32_t>(static_cast<unsigned char>(p[2])) << 8) |
           static_cast<std::uint32_t>(static_cast<unsigned char>(p[3]));
}

inline std::uint64_t read_be64(const char* p) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | static_cast<unsigned char>(p[i]);
    return v;
}

namespace detail {

// Key padded to the SHA-256 block size and XORed with the ipad/opad constant.
inline std::string xpad(const std::string& key, unsigned char x) {
    std::string blk(64, '\0');
    std::memcpy(&blk[0], key.data(), key.size() > 64 ? 64 : key.size());
    for (char& c : blk) c = static_cast<char>(static_cast<unsigned char>(c) ^ x);
    return blk;
}

inline std::string finish(EVP_MD_CTX* ctx) {
    unsigned char out[32];
    unsigned int len = 0;
    EVP_DigestFinal_ex(ctx, out, &len);
    return to_bytes(out, sizeof(out));
}

// f(k, st): Sum() of a k-level nested HMAC whose innermost SHA-256 accumulator
// currently holds st. ipad/opad hold the per-level pads of path[0..k).
inline std::string f(int k, EVP_MD_CTX* st, const std::vector<std::string>& ipad,
                     const std::vector<std::string>& opad) {
    if (k == 0) {
        // level 0 Sum(): SHA256(opad_of_salt || finalize(st))
        EVP_MD_CTX* outer = EVP_MD_CTX_new();
        EVP_DigestInit_ex(outer, EVP_sha256(), nullptr);
        const std::string o0 = xpad(kdf_salt, 0x5c);
        EVP_DigestUpdate(outer, o0.data(), o0.size());
        EVP_MD_CTX* copy = EVP_MD_CTX_new();
        EVP_MD_CTX_copy_ex(copy, st);
        const std::string digest = finish(copy);
        EVP_MD_CTX_free(copy);
        EVP_DigestUpdate(outer, digest.data(), digest.size());
        const std::string out = finish(outer);
        EVP_MD_CTX_free(outer);
        return out;
    }
    const std::string a = f(k - 1, st, ipad, opad);
    // The outer hash is level k-1: Reset() restores ipad_0..ipad_{k-1}, then the
    // opad of level k and the digest are appended.
    EVP_MD_CTX* st2 = EVP_MD_CTX_new();
    EVP_DigestInit_ex(st2, EVP_sha256(), nullptr);
    const std::string i0 = xpad(kdf_salt, 0x36);
    EVP_DigestUpdate(st2, i0.data(), i0.size());
    for (int j = 0; j < k - 1; ++j) EVP_DigestUpdate(st2, ipad[j].data(), ipad[j].size());
    EVP_DigestUpdate(st2, opad[k - 1].data(), opad[k - 1].size());
    EVP_DigestUpdate(st2, a.data(), a.size());
    const std::string out = f(k - 1, st2, ipad, opad);
    EVP_MD_CTX_free(st2);
    return out;
}

} // namespace detail

// VMess AEAD KDF: 32 bytes.
inline std::string kdf(const std::string& key, const std::vector<std::string>& path) {
    std::vector<std::string> ipad;
    std::vector<std::string> opad;
    EVP_MD_CTX* st = EVP_MD_CTX_new();
    EVP_DigestInit_ex(st, EVP_sha256(), nullptr);
    const std::string i0 = detail::xpad(kdf_salt, 0x36);
    EVP_DigestUpdate(st, i0.data(), i0.size());
    for (const std::string& p : path) {
        // New() only does inner.Write(ipad); the opad is written by Sum().
        ipad.push_back(detail::xpad(p, 0x36));
        opad.push_back(detail::xpad(p, 0x5c));
        EVP_DigestUpdate(st, ipad.back().data(), ipad.back().size());
    }
    EVP_DigestUpdate(st, key.data(), key.size());
    const std::string out = detail::f(static_cast<int>(path.size()), st, ipad, opad);
    EVP_MD_CTX_free(st);
    return out;
}

inline std::string kdf16(const std::string& key, const std::vector<std::string>& path) {
    return kdf(key, path).substr(0, 16);
}

// AES-GCM / ChaCha20-Poly1305 with a fixed 16-byte tag.
class Gcm {
public:
    bool init(const EVP_CIPHER* cipher, const std::string& key) {
        if (!cipher || key.size() != static_cast<std::size_t>(EVP_CIPHER_key_length(cipher)))
            return false;
        cipher_ = cipher;
        key_ = key;
        return true;
    }
    bool ok() const { return cipher_ != nullptr; }

    bool seal(const std::string& nonce, const std::string& aad, const std::string& in,
              std::string& out) const {
        return crypt(true, nonce, aad, in, out);
    }
    bool open(const std::string& nonce, const std::string& aad, const std::string& in,
              std::string& out) const {
        return crypt(false, nonce, aad, in, out);
    }

private:
    bool crypt(bool encrypt, const std::string& nonce, const std::string& aad,
               const std::string& in, std::string& out) const {
        if (!cipher_) return false;
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;
        bool ok = EVP_CipherInit_ex(ctx, cipher_, nullptr, nullptr, nullptr, encrypt ? 1 : 0) == 1;
        if (ok)
            ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, static_cast<int>(nonce.size()),
                                     nullptr) == 1;
        if (ok) {
            ok = EVP_CipherInit_ex(ctx, nullptr, nullptr,
                                   reinterpret_cast<const unsigned char*>(key_.data()),
                                   reinterpret_cast<const unsigned char*>(nonce.data()),
                                   encrypt ? 1 : 0) == 1;
        }
        int outl = 0;
        if (ok && !aad.empty()) {
            ok = EVP_CipherUpdate(ctx, nullptr, &outl,
                                  reinterpret_cast<const unsigned char*>(aad.data()),
                                  static_cast<int>(aad.size())) == 1;
        }
        if (!ok) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        if (encrypt) {
            out.assign(in.size() + 16, '\0');
            int fin = 0;
            ok = EVP_CipherUpdate(ctx, reinterpret_cast<unsigned char*>(&out[0]), &outl,
                                  reinterpret_cast<const unsigned char*>(in.data()),
                                  static_cast<int>(in.size())) == 1;
            if (ok)
                ok = EVP_CipherFinal_ex(ctx, reinterpret_cast<unsigned char*>(&out[0]) + outl,
                                        &fin) == 1;
            if (ok)
                ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16,
                                         reinterpret_cast<unsigned char*>(&out[0]) + outl + fin) == 1;
            EVP_CIPHER_CTX_free(ctx);
            return ok;
        }
        if (in.size() < 16) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        const std::size_t body = in.size() - 16;
        out.assign(body, '\0');
        int fin = 0;
        ok = EVP_CipherUpdate(ctx, reinterpret_cast<unsigned char*>(&out[0]), &outl,
                              reinterpret_cast<const unsigned char*>(in.data()),
                              static_cast<int>(body)) == 1;
        if (ok)
            ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16,
                                     const_cast<char*>(in.data()) + body) == 1;
        if (ok)
            ok = EVP_CipherFinal_ex(ctx, reinterpret_cast<unsigned char*>(&out[0]) + outl, &fin) == 1;
        EVP_CIPHER_CTX_free(ctx);
        return ok;
    }

    const EVP_CIPHER* cipher_ = nullptr;
    std::string key_;
};

// AES-128-ECB over a single block (the auth-ID check value).
inline bool aes128_ecb_decrypt_block(const std::string& key, const std::string& in,
                                     std::string& out) {
    if (key.size() != 16 || in.size() != 16) return false;
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    out.assign(16, '\0');
    int outl = 0, fin = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), nullptr,
                                 reinterpret_cast<const unsigned char*>(key.data()), nullptr) == 1;
    if (ok) ok = EVP_CIPHER_CTX_set_padding(ctx, 0) == 1;
    if (ok)
        ok = EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&out[0]), &outl,
                               reinterpret_cast<const unsigned char*>(in.data()), 16) == 1;
    if (ok) ok = EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&out[0]) + outl, &fin) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

// SHAKE128 stream, as used by Xray's ShakeSizeParser: every call consumes two
// bytes and is interpreted big-endian. OpenSSL can only emit the whole XOF
// output in one call, so the buffer is regenerated from the retained seed with
// twice the length whenever it runs dry.
class Shake128 {
public:
    explicit Shake128(const std::string& seed) : seed_(seed) {}

    std::uint16_t next() {
        if (pos_ + 2 > buf_.size()) refill();
        if (pos_ + 2 > buf_.size()) return 0;
        const std::uint16_t v = read_be16(buf_.data() + pos_);
        pos_ += 2;
        return v;
    }

    // NextPaddingLen(): next() % 64.
    std::uint16_t next_padding() { return static_cast<std::uint16_t>(next() % 64); }
    static constexpr std::uint16_t max_padding() { return 64; }

private:
    void refill() {
        // The XOF has to be re-derived from the seed, so the longer buffer is a
        // superset of the old one: reading has to continue at the same offset,
        // otherwise the whole mask sequence restarts and every following chunk
        // is decoded with the wrong mask.
        const std::size_t consumed = buf_.empty() ? 0 : pos_;
        std::size_t want = buf_.empty() ? 4096 : buf_.size() * 2;
        if (want > (1u << 20)) want = 1u << 20;
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        if (!ctx) return;
        if (EVP_DigestInit_ex(ctx, EVP_shake128(), nullptr) != 1) {
            EVP_MD_CTX_free(ctx);
            return;
        }
        EVP_DigestUpdate(ctx, seed_.data(), seed_.size());
        std::string out(want, '\0');
        if (EVP_DigestFinalXOF(ctx, reinterpret_cast<unsigned char*>(&out[0]), want) != 1) {
            EVP_MD_CTX_free(ctx);
            return;
        }
        EVP_MD_CTX_free(ctx);
        buf_.swap(out);
        pos_ = consumed;
    }

    std::string seed_;
    std::string buf_;
    std::size_t pos_ = 0;
};

} // namespace bpb::proxy::vmess
