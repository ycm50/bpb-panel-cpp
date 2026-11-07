#pragma once
#include <string>

namespace bpb::net {

// Self-signed certificate the proxy listener terminates TLS with.
//
// Xray 26.x refuses a VLESS outbound with security=none to any public address
// ("vless without TLS or other encryption is prohibited unless the server
// address is a private IP or domain"), so a direct-mode deployment has to
// speak TLS. A publicly trusted certificate needs a domain and an ACME
// challenge that an IP-only, non-standard-port deployment cannot satisfy, so
// the certificate is self-signed and the subscription pins its SHA-256
// (pinnedPeerCertSha256) -- trust comes from the pin, not from a CA.
struct CertInfo {
    bool ok = false;
    std::string subject;    // CN
    std::string not_after;  // human readable
    std::string sha256;     // lowercase hex, no separators
    std::string error;
};

// Creates cert/key (PEM) at the given paths when either is missing.
bool ensure_self_signed(const std::string& cert_path, const std::string& key_path,
                        const std::string& common_name, std::string& error);

// Reads an existing certificate and reports what the panel shows.
CertInfo inspect_cert(const std::string& cert_path);

// Regenerates unconditionally (panel regenerate button).
bool regenerate_self_signed(const std::string& cert_path, const std::string& key_path,
                            const std::string& common_name, std::string& error);

} // namespace bpb::net
