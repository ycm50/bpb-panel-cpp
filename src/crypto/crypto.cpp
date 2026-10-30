#include "crypto/crypto.h"
#include "util/util.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

namespace bpb::crypto {

std::vector<std::uint8_t> random_bytes(std::size_t len) {
    std::vector<std::uint8_t> buf(len);
    if (RAND_bytes(buf.data(), static_cast<int>(len)) != 1) buf.assign(len, 0);
    return buf;
}

std::string random_hex(std::size_t bytes) {
    auto buf = random_bytes(bytes);
    return hex_encode(buf.data(), buf.size());
}

static std::string digest_hex(const EVP_MD* md, std::string_view data) {
    unsigned int len = 0;
    unsigned char out[EVP_MAX_MD_SIZE];
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, nullptr);
    EVP_DigestUpdate(ctx, data.data(), data.size());
    EVP_DigestFinal_ex(ctx, out, &len);
    EVP_MD_CTX_free(ctx);
    return hex_encode(out, len);
}

std::string sha224_hex(std::string_view data) { return digest_hex(EVP_sha224(), data); }
std::string sha256_hex(std::string_view data) { return digest_hex(EVP_sha256(), data); }

std::string hmac_sha256(std::string_view key, std::string_view data) {
    unsigned int len = 0;
    unsigned char out[EVP_MAX_MD_SIZE];
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.data()), data.size(), out, &len);
    return std::string(reinterpret_cast<char*>(out), len);
}

std::string hmac_sha256_hex(std::string_view key, std::string_view data) {
    std::string raw = hmac_sha256(key, data);
    return hex_encode(reinterpret_cast<const std::uint8_t*>(raw.data()), raw.size());
}

bool constant_time_equals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (std::size_t i = 0; i < a.size(); ++i) diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    return diff == 0;
}

std::string jwt_sign_hs256(std::string_view payload_json, std::string_view secret) {
    std::string header = R"({"alg":"HS256","typ":"JWT"})";
    std::string signing_input = base64url_encode(header) + "." + base64url_encode(payload_json);
    std::string sig = hmac_sha256(secret, signing_input);
    return signing_input + "." + base64url_encode(sig);
}

std::string jwt_payload(std::string_view token) {
    auto parts = split(token, '.');
    if (parts.size() != 3) return "";
    return base64_decode(parts[1]);
}

bool jwt_verify_hs256(std::string_view token, std::string_view secret, std::string& payload_json) {
    auto parts = split(token, '.');
    if (parts.size() != 3) return false;
    std::string signing_input = parts[0] + "." + parts[1];
    std::string expected = hmac_sha256(secret, signing_input);
    std::string actual = base64_decode(parts[2]);
    if (!constant_time_equals(expected, actual)) return false;
    payload_json = base64_decode(parts[1]);
    return true;
}

} // namespace bpb::crypto
