#include "net/selfsigned.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>

namespace bpb::net {

namespace {

std::string hex_lower(const unsigned char* p, std::size_t n) {
    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) {
        out += d[p[i] >> 4];
        out += d[p[i] & 15];
    }
    return out;
}

bool file_exists(const std::string& p) {
    std::error_code ec;
    return std::filesystem::exists(p, ec) && !ec;
}

// PEM output through a memory BIO. See regenerate_self_signed(): passing a FILE*
// to OpenSSL crashes on Windows ("no OPENSSL_Applink") because the DLL and this
// binary do not share a CRT.
bool pem_to_string(X509* cert, std::string& out) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return false;
    const bool ok = PEM_write_bio_X509(bio, cert) == 1;
    if (ok) {
        char* data = nullptr;
        const long len = BIO_get_mem_data(bio, &data);
        if (len > 0 && data) out.assign(data, static_cast<std::size_t>(len));
    }
    BIO_free(bio);
    return ok && !out.empty();
}

bool key_to_string(EVP_PKEY* key, std::string& out) {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) return false;
    const bool ok = PEM_write_bio_PrivateKey(bio, key, nullptr, nullptr, 0, nullptr, nullptr) == 1;
    if (ok) {
        char* data = nullptr;
        const long len = BIO_get_mem_data(bio, &data);
        if (len > 0 && data) out.assign(data, static_cast<std::size_t>(len));
    }
    BIO_free(bio);
    return ok && !out.empty();
}

bool write_bytes(const std::string& path, const std::string& data) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) return false;
    f.write(data.data(), static_cast<std::streamsize>(data.size()));
    return static_cast<bool>(f);
}

// Builds a self-signed X509 with the given CN, plus a SAN that matches it.
// The SAN matters: Xray's verifyPeerCertByName and every browser ignore the
// legacy CN field, so a certificate without a SAN is treated as nameless.
X509* make_cert(const std::string& cn, EVP_PKEY* key) {
    X509* x = X509_new();
    if (!x) return nullptr;
    X509_set_version(x, 2);  // v3
    ASN1_INTEGER_set(X509_get_serialNumber(x),
                     static_cast<long>(std::time(nullptr)) & 0x7fffffff);
    X509_gmtime_adj(X509_get_notBefore(x), 0);
    X509_gmtime_adj(X509_get_notAfter(x), 60L * 60 * 24 * 3650);
    X509_set_pubkey(x, key);

    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
    X509_set_issuer_name(x, name);

    // subjectAltName: the host as a DNS name when it has letters, else as an IP.
    const bool looks_like_ip =
        !cn.empty() && cn.find_first_not_of("0123456789.") == std::string::npos;
    std::string san = looks_like_ip ? ("IP:" + cn) : ("DNS:" + cn);
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, x, x, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, NID_subject_alt_name,
                                              const_cast<char*>(san.c_str()));
    if (ext) {
        X509_add_ext(x, ext, -1);
        X509_EXTENSION_free(ext);
    }
    // basicConstraints CA:FALSE -- this is a leaf, not a CA.
    X509_EXTENSION* bc = X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints,
                                             const_cast<char*>("CA:FALSE"));
    if (bc) {
        X509_add_ext(x, bc, -1);
        X509_EXTENSION_free(bc);
    }
    if (!X509_sign(x, key, EVP_sha256())) {
        X509_free(x);
        return nullptr;
    }
    return x;
}

} // namespace

bool regenerate_self_signed(const std::string& cert_path, const std::string& key_path,
                            const std::string& common_name, std::string& error) {
    const std::string cn = common_name.empty() ? "bpb.local" : common_name;

    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!pctx) {
        error = "EVP_PKEY_CTX_new_id failed";
        return false;
    }
    EVP_PKEY* key = nullptr;
    bool ok = EVP_PKEY_keygen_init(pctx) == 1 &&
              EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) == 1 &&
              EVP_PKEY_keygen(pctx, &key) == 1;
    EVP_PKEY_CTX_free(pctx);
    if (!ok || !key) {
        error = "RSA key generation failed";
        if (key) EVP_PKEY_free(key);
        return false;
    }

    X509* cert = make_cert(cn, key);
    if (!cert) {
        EVP_PKEY_free(key);
        error = "certificate creation failed";
        return false;
    }

    // Serialise through a memory BIO and write with ofstream, never with a FILE*
    // handed to OpenSSL. On Windows the OpenSSL DLL uses a different CRT than
    // this binary, so PEM_write_* on a FILE* the app opened dies with
    // "OPENSSL_Uplink(...): no OPENSSL_Applink" -- the process aborted on the
    // very first start, before the listener was up.
    std::string cert_pem;
    std::string key_pem;
    bool ok_pem = pem_to_string(cert, cert_pem);
    if (ok_pem) ok_pem = key_to_string(key, key_pem);

    X509_free(cert);
    EVP_PKEY_free(key);
    if (!ok_pem) {
        error = "could not serialise the certificate";
        return false;
    }
    if (!write_bytes(cert_path, cert_pem) || !write_bytes(key_path, key_pem)) {
        error = "could not write certificate files";
        return false;
    }
    // The key is a private secret: keep it owner-only like the password file.
    std::error_code ec;
    std::filesystem::permissions(key_path, std::filesystem::perms::owner_read |
                                             std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace, ec);
    return true;
}

bool ensure_self_signed(const std::string& cert_path, const std::string& key_path,
                        const std::string& common_name, std::string& error) {
    if (file_exists(cert_path) && file_exists(key_path)) return true;
    return regenerate_self_signed(cert_path, key_path, common_name, error);
}

CertInfo inspect_cert(const std::string& cert_path) {
    CertInfo info;
    std::ifstream in(cert_path, std::ios::binary);
    if (!in) {
        info.error = "certificate not found: " + cert_path;
        return info;
    }
    std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    // Same reason as the writer: no FILE* crosses into OpenSSL on Windows.
    BIO* bio = BIO_new_mem_buf(text.data(), static_cast<int>(text.size()));
    if (!bio) {
        info.error = "cannot allocate a BIO for " + cert_path;
        return info;
    }
    X509* x = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!x) {
        info.error = "certificate is not readable PEM";
        return info;
    }
    char cn[256] = {0};
    X509_NAME_get_text_by_NID(X509_get_subject_name(x), NID_commonName, cn, sizeof(cn));
    info.subject = cn;

    char when[64] = {0};
    const ASN1_TIME* na = X509_get0_notAfter(x);
    if (na) {
        BIO* b = BIO_new(BIO_s_mem());
        if (b) {
            ASN1_TIME_print(b, na);
            char buf[64] = {0};
            BIO_read(b, buf, sizeof(buf) - 1);
            BIO_free(b);
            std::snprintf(when, sizeof(when), "%s", buf);
        }
    }
    info.not_after = when;

    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    // digest of the DER form: the certificate fingerprint a client pins.
    if (X509_digest(x, EVP_sha256(), md, &md_len) == 1) info.sha256 = hex_lower(md, md_len);
    X509_free(x);
    info.ok = !info.sha256.empty();
    return info;
}

} // namespace bpb::net
