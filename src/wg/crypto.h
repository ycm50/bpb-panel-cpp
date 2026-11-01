#pragma once
#include <cstdint>
#include <cstddef>
#include <string>

namespace bpb::wg {

struct KeyPair {
    unsigned char priv[32]{};
    unsigned char pub[32]{};
};

bool generate_keypair(KeyPair& kp);
bool x25519_public(const unsigned char priv[32], unsigned char pub[32]);
bool x25519_shared(const unsigned char priv[32], const unsigned char peer_pub[32], unsigned char out[32]);

// BLAKE2s-256 unkeyed
void blake2s256(const void* data, std::size_t len, unsigned char out[32]);
// BLAKE2s keyed, arbitrary digest size (used for mac1 / cookie)
void blake2s_keyed(const unsigned char* key, std::size_t key_len, const void* data,
                   std::size_t len, unsigned char* out, std::size_t out_len);

// Standard HMAC-BLAKE2s256 (what WireGuard's KDF is built on).
void hmac_blake2s(const unsigned char* key, std::size_t key_len, const void* data, std::size_t len,
                  unsigned char out[32]);

// WireGuard KDF (RFC 5869 style, HMAC-BLAKE2s):
//   KDF1: out1
//   KDF2: out1, out2
//   KDF3: out1, out2, out3
void kdf1(const unsigned char key[32], const void* input, std::size_t input_len, unsigned char out1[32]);
void kdf2(const unsigned char key[32], const void* input, std::size_t input_len,
          unsigned char out1[32], unsigned char out2[32]);
void kdf3(const unsigned char key[32], const void* input, std::size_t input_len,
          unsigned char out1[32], unsigned char out2[32], unsigned char out3[32]);

// ChaCha20-Poly1305 AEAD; counter is placed in nonce[4..12) little-endian.
bool aead_seal(const unsigned char key[32], std::uint64_t counter, const void* plaintext,
               std::size_t len, const void* ad, std::size_t ad_len, unsigned char* out_with_tag);
bool aead_open(const unsigned char key[32], std::uint64_t counter, const void* in_with_tag,
               std::size_t len, const void* ad, std::size_t ad_len, unsigned char* out);

void tai64n_now(unsigned char out[12]);

std::string base64_encode(const unsigned char* data, std::size_t len);
bool base64_decode(const std::string& in, unsigned char* out, std::size_t out_len);

std::uint32_t monotonic_ms();

} // namespace bpb::wg
