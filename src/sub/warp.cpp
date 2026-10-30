#include "sub/warp.h"
#include "net/http_client.h"
#include "util/util.h"

#include <openssl/evp.h>

namespace bpb::sub {

namespace {

struct WarpKeys {
    std::string public_key;
    std::string private_key;
};

bool generate_keys(WarpKeys& keys, std::string& error) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx) {
        error = "EVP_PKEY_CTX_new_id failed";
        return false;
    }
    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        error = "x25519 keygen failed";
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    unsigned char pub[32];
    unsigned char priv[32];
    std::size_t pub_len = sizeof(pub);
    std::size_t priv_len = sizeof(priv);
    bool ok = EVP_PKEY_get_raw_public_key(pkey, pub, &pub_len) > 0 &&
              EVP_PKEY_get_raw_private_key(pkey, priv, &priv_len) > 0;
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    if (!ok) {
        error = "cannot export x25519 keys";
        return false;
    }
    keys.public_key = base64_encode(pub, pub_len);
    keys.private_key = base64_encode(priv, priv_len);
    return true;
}

bool register_account(const WarpKeys& keys, nlohmann::json& out, std::string& error) {
    nlohmann::json body = {
        {"install_id", ""},        {"fcm_token", ""},
        {"tos", iso_time_now()},   {"type", "Android"},
        {"model", "PC"},           {"locale", "en_US"},
        {"warp_enabled", true},    {"key", keys.public_key}};

    net::httpc::Response res;
    if (!net::httpc::post("https://api.cloudflareclient.com/v0a4005/reg", body.dump(), res, error,
                          15000,
                          {{"Content-Type", "application/json"}, {"User-Agent", "insomnia/13.0.2"}})) {
        return false;
    }
    if (res.status < 200 || res.status >= 300) {
        error = "warp api status " + std::to_string(res.status) + ": " + res.body.substr(0, 120);
        return false;
    }
    try {
        out = nlohmann::json::parse(res.body);
    } catch (const std::exception& e) {
        error = std::string("warp api json parse failed: ") + e.what();
        return false;
    }
    return true;
}

} // namespace

bool fetch_warp_accounts(nlohmann::json& accounts, std::string& error) {
    nlohmann::json result = nlohmann::json::array();
    for (int i = 0; i < 2; ++i) {
        WarpKeys keys;
        if (!generate_keys(keys, error)) return false;
        nlohmann::json reg;
        if (!register_account(keys, reg, error)) return false;
        try {
            std::string v6 = reg["config"]["interface"]["addresses"]["v6"].get<std::string>();
            std::string client_id = reg["config"]["client_id"].get<std::string>();
            std::string peer_key = reg["config"]["peers"][0]["public_key"].get<std::string>();
            result.push_back({{"privateKey", keys.private_key},
                              {"publicKey", peer_key},
                              {"warpIPv6", v6 + "/128"},
                              {"reserved", client_id}});
        } catch (const std::exception& e) {
            error = std::string("unexpected warp api response: ") + e.what();
            return false;
        }
    }
    accounts = result;
    return true;
}

} // namespace bpb::sub
