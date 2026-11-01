#include "wg/crypto.h"

#include <openssl/evp.h>
#include <openssl/rand.h>

#include <chrono>
#include <cstring>
#include <vector>

namespace bpb::wg {

namespace {

void put_le64(unsigned char* out, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) out[i] = static_cast<unsigned char>((v >> (i * 8)) & 0xFF);
}

// HMAC-BLAKE2s over one or two input chunks (EVP_MAC, non-deprecated path).
void hmac_blake2s2(const unsigned char* key, std::size_t key_len, const void* in0,
                   std::size_t in0_len, const void* in1, std::size_t in1_len, unsigned char out[32]) {
    static EVP_MAC* mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
    char digest[] = "BLAKE2S-256";
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", digest, 0);
    params[1] = OSSL_PARAM_construct_end();

    std::size_t written = 0;
    bool ok = EVP_MAC_init(ctx, key, key_len, params) == 1;
    if (ok && in0 && in0_len) ok = EVP_MAC_update(ctx, static_cast<const unsigned char*>(in0), in0_len) == 1;
    if (ok && in1 && in1_len) ok = EVP_MAC_update(ctx, static_cast<const unsigned char*>(in1), in1_len) == 1;
    if (ok) ok = EVP_MAC_final(ctx, out, &written, 32) == 1;
    EVP_MAC_CTX_free(ctx);

    if (!ok || written != 32) {
        // explicit fallback: HMAC(K, m) = H((K^opad) || H((K^ipad) || m))
        unsigned char k0[64] = {0};
        std::memcpy(k0, key, key_len > 64 ? 64 : key_len);
        unsigned char ipad[64], opad[64];
        for (int i = 0; i < 64; ++i) {
            ipad[i] = static_cast<unsigned char>(k0[i] ^ 0x36);
            opad[i] = static_cast<unsigned char>(k0[i] ^ 0x5C);
        }
        unsigned char inner[32];
        std::vector<unsigned char> buf;
        buf.insert(buf.end(), ipad, ipad + 64);
        if (in0 && in0_len) buf.insert(buf.end(), static_cast<const unsigned char*>(in0),
                                       static_cast<const unsigned char*>(in0) + in0_len);
        if (in1 && in1_len) buf.insert(buf.end(), static_cast<const unsigned char*>(in1),
                                       static_cast<const unsigned char*>(in1) + in1_len);
        blake2s256(buf.data(), buf.size(), inner);

        std::vector<unsigned char> outer;
        outer.insert(outer.end(), opad, opad + 64);
        outer.insert(outer.end(), inner, inner + 32);
        blake2s256(outer.data(), outer.size(), out);
    }
}

} // namespace

bool generate_keypair(KeyPair& kp) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx) return false;
    bool ok = EVP_PKEY_keygen_init(ctx) > 0;
    EVP_PKEY* pkey = nullptr;
    ok = ok && EVP_PKEY_keygen(ctx, &pkey) > 0;
    if (ok) {
        std::size_t len = 32;
        ok = EVP_PKEY_get_raw_private_key(pkey, kp.priv, &len) > 0 && len == 32;
        len = 32;
        ok = ok && EVP_PKEY_get_raw_public_key(pkey, kp.pub, &len) > 0 && len == 32;
    }
    if (pkey) EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

bool x25519_public(const unsigned char priv[32], unsigned char pub[32]) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv, 32);
    if (!pkey) return false;
    std::size_t len = 32;
    bool ok = EVP_PKEY_get_raw_public_key(pkey, pub, &len) > 0 && len == 32;
    EVP_PKEY_free(pkey);
    return ok;
}

bool x25519_shared(const unsigned char priv[32], const unsigned char peer_pub[32],
                   unsigned char out[32]) {
    EVP_PKEY* mine = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv, 32);
    EVP_PKEY* theirs = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pub, 32);
    bool ok = false;
    if (mine && theirs) {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(mine, nullptr);
        if (ctx) {
            std::size_t len = 32;
            ok = EVP_PKEY_derive_init(ctx) > 0 && EVP_PKEY_derive_set_peer(ctx, theirs) > 0 &&
                 EVP_PKEY_derive(ctx, out, &len) > 0 && len == 32;
            EVP_PKEY_CTX_free(ctx);
        }
    }
    if (mine) EVP_PKEY_free(mine);
    if (theirs) EVP_PKEY_free(theirs);
    return ok;
}

void blake2s256(const void* data, std::size_t len, unsigned char out[32]) {
    unsigned int out_len = 32;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_blake2s256(), nullptr);
    EVP_DigestUpdate(ctx, data, len);
    EVP_DigestFinal_ex(ctx, out, &out_len);
    EVP_MD_CTX_free(ctx);
}

void blake2s_keyed(const unsigned char* key, std::size_t key_len, const void* data,
                   std::size_t len, unsigned char* out, std::size_t out_len) {
    unsigned int digest_size = static_cast<unsigned int>(out_len);  // bytes, not bits
    EVP_MAC* mac = EVP_MAC_fetch(nullptr, "BLAKE2SMAC", nullptr);
    if (mac) {
        EVP_MAC_CTX* ctx = EVP_MAC_CTX_new(mac);
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_uint("size", &digest_size);
        params[1] = OSSL_PARAM_construct_end();
        std::size_t produced = 0;
        bool ok = EVP_MAC_init(ctx, key, key_len, params) == 1 &&
                  EVP_MAC_update(ctx, static_cast<const unsigned char*>(data), len) == 1 &&
                  EVP_MAC_final(ctx, out, &produced, out_len) == 1 && produced == out_len;
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
        if (ok) return;
    }
    std::memset(out, 0, out_len);
}

void hmac_blake2s(const unsigned char* key, std::size_t key_len, const void* data, std::size_t len,
                  unsigned char out[32]) {
    hmac_blake2s2(key, key_len, data, len, nullptr, 0, out);
}

void kdf1(const unsigned char key[32], const void* input, std::size_t input_len,
          unsigned char out1[32]) {
    unsigned char prk[32];
    hmac_blake2s(key, 32, input, input_len, prk);
    const unsigned char one = 0x01;
    hmac_blake2s(prk, 32, &one, 1, out1);
}

void kdf2(const unsigned char key[32], const void* input, std::size_t input_len,
          unsigned char out1[32], unsigned char out2[32]) {
    unsigned char prk[32];
    hmac_blake2s(key, 32, input, input_len, prk);

    const unsigned char one = 0x01, two = 0x02;
    unsigned char t0[32];
    hmac_blake2s(prk, 32, &one, 1, t0);

    unsigned char t1[32];
    hmac_blake2s2(prk, 32, t0, 32, &two, 1, t1);

    if (out1) std::memcpy(out1, t0, 32);
    if (out2) std::memcpy(out2, t1, 32);
}

void kdf3(const unsigned char key[32], const void* input, std::size_t input_len,
          unsigned char out1[32], unsigned char out2[32], unsigned char out3[32]) {
    unsigned char prk[32];
    hmac_blake2s(key, 32, input, input_len, prk);

    const unsigned char one = 0x01, two = 0x02, three = 0x03;
    unsigned char t0[32], t1[32], t2[32];
    hmac_blake2s(prk, 32, &one, 1, t0);
    hmac_blake2s2(prk, 32, t0, 32, &two, 1, t1);
    hmac_blake2s2(prk, 32, t1, 32, &three, 1, t2);

    if (out1) std::memcpy(out1, t0, 32);
    if (out2) std::memcpy(out2, t1, 32);
    if (out3) std::memcpy(out3, t2, 32);
}

bool aead_seal(const unsigned char key[32], std::uint64_t counter, const void* plaintext,
               std::size_t len, const void* ad, std::size_t ad_len, unsigned char* out_with_tag) {
    unsigned char nonce[12] = {0};
    put_le64(nonce + 4, counter);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int outl = 0;
    bool ok = EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1 &&
              EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1;
    if (ok && ad_len)
        ok = EVP_EncryptUpdate(ctx, nullptr, &outl, static_cast<const unsigned char*>(ad),
                               static_cast<int>(ad_len)) == 1;
    if (ok && len)
        ok = EVP_EncryptUpdate(ctx, out_with_tag, &outl,
                               static_cast<const unsigned char*>(plaintext),
                               static_cast<int>(len)) == 1;
    int fin = 0;
    if (ok) ok = EVP_EncryptFinal_ex(ctx, out_with_tag + outl, &fin) == 1;
    if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, out_with_tag + len) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

bool aead_open(const unsigned char key[32], std::uint64_t counter, const void* in_with_tag,
               std::size_t len, const void* ad, std::size_t ad_len, unsigned char* out) {
    unsigned char nonce[12] = {0};
    put_le64(nonce + 4, counter);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;
    int outl = 0;
    bool ok = EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) == 1 &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) == 1 &&
              EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) == 1;
    if (ok && ad_len)
        ok = EVP_DecryptUpdate(ctx, nullptr, &outl, static_cast<const unsigned char*>(ad),
                               static_cast<int>(ad_len)) == 1;
    if (ok && len)
        ok = EVP_DecryptUpdate(ctx, out, &outl, static_cast<const unsigned char*>(in_with_tag),
                               static_cast<int>(len)) == 1;
    unsigned char tag[16];
    std::memcpy(tag, static_cast<const unsigned char*>(in_with_tag) + len, 16);
    if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag) == 1;
    int fin = 0;
    if (ok) ok = EVP_DecryptFinal_ex(ctx, out + outl, &fin) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

void tai64n_now(unsigned char out[12]) {
    using namespace std::chrono;
    auto now = system_clock::now().time_since_epoch();
    auto secs = duration_cast<seconds>(now).count();
    auto nanos = duration_cast<nanoseconds>(now - seconds(secs)).count();

    std::uint64_t tai = 0x400000000000000aULL + static_cast<std::uint64_t>(secs) + 37ULL;
    for (int i = 0; i < 8; ++i)
        out[i] = static_cast<unsigned char>((tai >> ((7 - i) * 8)) & 0xFF);
    std::uint32_t ns = static_cast<std::uint32_t>(nanos);
    out[8] = static_cast<unsigned char>((ns >> 24) & 0xFF);
    out[9] = static_cast<unsigned char>((ns >> 16) & 0xFF);
    out[10] = static_cast<unsigned char>((ns >> 8) & 0xFF);
    out[11] = static_cast<unsigned char>(ns & 0xFF);
}

std::uint32_t monotonic_ms() {
    using namespace std::chrono;
    static const auto start = steady_clock::now();
    return static_cast<std::uint32_t>(
        duration_cast<milliseconds>(steady_clock::now() - start).count());
}

std::string base64_encode(const unsigned char* data, std::size_t len) {
    std::string out(4 * ((len + 2) / 3) + 1, '\0');
    int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), data,
                            static_cast<int>(len));
    out.resize(n > 0 ? static_cast<std::size_t>(n) : 0);
    return out;
}

bool base64_decode(const std::string& in, unsigned char* out, std::size_t out_len) {
    static int table[256];
    static bool ready = false;
    if (!ready) {
        std::memset(table, -1, sizeof(table));
        const char* a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (int i = 0; i < 64; ++i) table[static_cast<unsigned char>(a[i])] = i;
        ready = true;
    }
    std::size_t produced = 0;
    std::uint32_t buf = 0;
    int bits = 0;
    for (char c : in) {
        if (c == '=' || c == '\n' || c == '\r') continue;
        int v = table[static_cast<unsigned char>(c)];
        if (v < 0) return false;
        buf = (buf << 6) | static_cast<std::uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (produced >= out_len) return false;
            out[produced++] = static_cast<unsigned char>((buf >> bits) & 0xFF);
        }
    }
    return produced == out_len;
}

} // namespace bpb::wg
