#include "wg/device.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace bpb::wg {

namespace {

constexpr std::uint8_t kInitiation = 1;
constexpr std::uint8_t kResponse = 2;
constexpr std::uint8_t kCookieReply = 3;
constexpr std::uint8_t kTransport = 4;

constexpr std::size_t kInitiationSize = 148;
constexpr std::size_t kResponseSize = 92;
constexpr std::size_t kTransportHeader = 16;
constexpr std::size_t kTag = 16;

const char kConstruction[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const char kIdentifier[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
const char kLabelMac1[] = "mac1----";

// hash = BLAKE2s(hash || data)
void mix_hash(unsigned char hash[32], const void* data, std::size_t len) {
    unsigned char buf[32 + 256];
    if (len <= 256) {
        std::memcpy(buf, hash, 32);
        std::memcpy(buf + 32, data, len);
        blake2s256(buf, 32 + len, hash);
        return;
    }
    std::vector<unsigned char> big(32 + len);
    std::memcpy(big.data(), hash, 32);
    std::memcpy(big.data() + 32, data, len);
    blake2s256(big.data(), big.size(), hash);
}

void put_le32(unsigned char* p, std::uint32_t v) {
    p[0] = static_cast<unsigned char>(v & 0xFF);
    p[1] = static_cast<unsigned char>((v >> 8) & 0xFF);
    p[2] = static_cast<unsigned char>((v >> 16) & 0xFF);
    p[3] = static_cast<unsigned char>((v >> 24) & 0xFF);
}

std::uint32_t rd_le32(const unsigned char* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}

void put_le64(unsigned char* p, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = static_cast<unsigned char>((v >> (i * 8)) & 0xFF);
}

std::uint64_t rd_le64(const unsigned char* p) {
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}

// WARP packs a 3-byte account tag into the high bytes of the little-endian
// message type. Xray-core's wireguard bind does exactly this on send and clears
// the same bytes on receive, so the rest of the stack still sees a plain
// uint32 type.
inline void apply_reserved(unsigned char* buf, std::size_t len, const unsigned char rsv[3]) {
    if (len <= 3) return;
    buf[1] = rsv[0];
    buf[2] = rsv[1];
    buf[3] = rsv[2];
}

inline void strip_reserved(unsigned char* buf, std::size_t len) {
    if (len <= 3) return;
    buf[1] = 0;
    buf[2] = 0;
    buf[3] = 0;
}

bool parse_ipv4(const std::string& s, std::uint32_t& out) {
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (std::sscanf(s.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    out = (a << 24) | (b << 16) | (c << 8) | d;
    return true;
}

bool parse_ipv6(const std::string& s, unsigned char out[16]) {
    std::string t = s;
    auto slash = t.find('/');
    if (slash != std::string::npos) t = t.substr(0, slash);
    std::memset(out, 0, 16);
    return inet_pton(AF_INET6, t.c_str(), out) == 1;
}

} // namespace

bool Device::configure(const PeerConfig& cfg, std::string& error) {
    std::memcpy(reserved_, cfg.reserved, sizeof(reserved_));
    has_reserved_ = cfg.has_reserved;
    if (!base64_decode(cfg.private_key_b64, static_priv_, 32)) {
        error = "invalid private key";
        return false;
    }
    if (!base64_decode(cfg.peer_public_b64, peer_pub_, 32)) {
        error = "invalid peer public key";
        return false;
    }
    if (!x25519_public(static_priv_, static_pub_)) {
        error = "cannot derive local public key";
        return false;
    }
    if (!cfg.local_ipv4.empty() && !parse_ipv4(cfg.local_ipv4, local_v4_)) {
        error = "invalid local ipv4";
        return false;
    }
    if (!cfg.local_ipv6.empty() && !parse_ipv6(cfg.local_ipv6, local_v6_)) {
        error = "invalid local ipv6";
        return false;
    }
    mtu_ = cfg.mtu > 0 ? cfg.mtu : 1280;
    keepalive_seconds_ = cfg.keepalive_seconds > 0 ? cfg.keepalive_seconds : 25;
    return true;
}

bool Device::initiate(std::string& error) {
    // Rate-limit re-initiations: hammering the endpoint both wastes handshakes
    // and invalidates the index an in-flight response would carry.
    std::uint32_t now = monotonic_ms();
    if (awaiting_response_ && (now - last_initiate_ms_) < 1000u) {
        error = "handshake already in flight";
        return false;
    }
    if (!build_initiation(error)) return false;
    last_initiate_ms_ = monotonic_ms();
    return true;
}

bool Device::build_initiation(std::string& error) {
    // InitialChainKey = BLAKE2s(NoiseConstruction)
    unsigned char initial_chain[32];
    blake2s256(kConstruction, std::strlen(kConstruction), initial_chain);
    // InitialHash = mixHash(InitialChainKey, WGIdentifier)
    unsigned char initial_hash[32];
    std::memcpy(initial_hash, initial_chain, 32);
    mix_hash(initial_hash, kIdentifier, std::strlen(kIdentifier));

    std::memcpy(chain_key_, initial_chain, 32);
    std::memcpy(hash_, initial_hash, 32);

    KeyPair eph;
    if (!generate_keypair(eph)) {
        error = "cannot generate ephemeral key";
        return false;
    }
    std::memcpy(ephemeral_priv_, eph.priv, 32);
    std::memcpy(ephemeral_pub_, eph.pub, 32);

    // hash = HASH(hash || Spub_peer)
    mix_hash(hash_, peer_pub_, 32);

    std::vector<unsigned char> msg(kInitiationSize, 0);
    put_le32(msg.data(), kInitiation);
    local_index_ = static_cast<std::uint32_t>(monotonic_ms() ^ (std::rand() << 16));
    if (local_index_ == 0) local_index_ = 1;
    put_le32(msg.data() + 4, local_index_);
    std::memcpy(msg.data() + 8, ephemeral_pub_, 32);

    // ck = KDF1(ck, Epub); hash = HASH(hash || Epub)
    unsigned char tmp[32];
    kdf1(chain_key_, ephemeral_pub_, 32, tmp);
    std::memcpy(chain_key_, tmp, 32);
    mix_hash(hash_, ephemeral_pub_, 32);

    // (ck, k) = KDF2(ck, DH(e_priv, Spub_peer))
    unsigned char ss[32], key[32];
    if (!x25519_shared(ephemeral_priv_, peer_pub_, ss)) {
        error = "ephemeral DH failed";
        return false;
    }
    kdf2(chain_key_, ss, 32, chain_key_, key);

    // encrypted_static = AEAD(k, 0, Spub_ours, ad = hash)
    if (!aead_seal(key, 0, static_pub_, 32, hash_, 32, msg.data() + 40)) {
        error = "AEAD(static) failed";
        return false;
    }
    mix_hash(hash_, msg.data() + 40, 48);

    // (ck, k) = KDF2(ck, DH(s_priv, Spub_peer))
    if (!x25519_shared(static_priv_, peer_pub_, ss)) {
        error = "static DH failed";
        return false;
    }
    kdf2(chain_key_, ss, 32, chain_key_, key);

    // encrypted_timestamp = AEAD(k, 0, tai64n, ad = hash)
    unsigned char ts[12];
    tai64n_now(ts);
    if (!aead_seal(key, 0, ts, 12, hash_, 32, msg.data() + 88)) {
        error = "AEAD(timestamp) failed";
        return false;
    }
    mix_hash(hash_, msg.data() + 88, 28);

    // mac1 = MAC(BLAKE2s-128 key = HASH(mac1label || Spub_peer))
    unsigned char mac_key[32], mac1[16];
    unsigned char label[40];
    std::memcpy(label, kLabelMac1, 8);
    std::memcpy(label + 8, peer_pub_, 32);
    blake2s256(label, sizeof(label), mac_key);
    blake2s_keyed(mac_key, 32, msg.data(), kInitiationSize - 32, mac1, 16);
    std::memcpy(msg.data() + kInitiationSize - 32, mac1, 16);
    // mac2 stays zero (we have no valid cookie yet)

    if (has_reserved_) apply_reserved(msg.data(), msg.size(), reserved_);
    if (!send_ || !send_(msg.data(), msg.size())) {
        error = "send handshake initiation failed";
        return false;
    }
    awaiting_response_ = true;
    return true;
}

bool Device::consume_response(const unsigned char* data, std::size_t len) {
    if (len != kResponseSize) return false;
    if (rd_le32(data) != kResponse) return false;

    std::uint32_t sender = rd_le32(data + 4);
    std::uint32_t receiver = rd_le32(data + 8);
    if (receiver != local_index_) return false;  // not for this handshake
    remote_index_ = sender;

    const unsigned char* epub = data + 12;
    const unsigned char* empty = data + 44;  // 16 bytes AEAD tag

    unsigned char h[32], ck[32];
    std::memcpy(h, hash_, 32);
    std::memcpy(ck, chain_key_, 32);

    // hash = HASH(hash || Epub); ck = KDF1(ck, Epub)
    mix_hash(h, epub, 32);
    unsigned char tmp[32];
    kdf1(ck, epub, 32, tmp);
    std::memcpy(ck, tmp, 32);

    // ck = KDF1(ck, DH(e_priv, Epub))
    unsigned char ss[32];
    if (!x25519_shared(ephemeral_priv_, epub, ss)) return false;
    kdf1(ck, ss, 32, tmp);
    std::memcpy(ck, tmp, 32);

    // ck = KDF1(ck, DH(s_priv, Epub))
    if (!x25519_shared(static_priv_, epub, ss)) return false;
    kdf1(ck, ss, 32, tmp);
    std::memcpy(ck, tmp, 32);

    // psk is zero for standard WireGuard (no preshared key).
    unsigned char zero_psk[32] = {0};
    unsigned char tau[32], key[32];
    kdf3(ck, zero_psk, 32, ck, tau, key);
    mix_hash(h, tau, 32);

    // verify AEAD(empty) with ad = hash
    unsigned char plain[1];
    if (!aead_open(key, 0, empty, 0, h, 32, plain)) return false;
    mix_hash(h, empty, 16);

    // Derive the two transport keys from the *new chaining key* (KDF3's first
    // output), not from the AEAD key. Initiator: send=t0, recv=t1.
    kdf2(ck, nullptr, 0, send_key_, recv_key_);

    have_keys_ = true;
    last_rx_ms_ = monotonic_ms();  // handshake response counted as peer activity
    awaiting_response_ = false;
    send_counter_ = 0;
    recv_counter_ = 0;
    recv_bitmap_ = 0;
    last_handshake_ms_ = monotonic_ms();
    last_send_ms_ = last_handshake_ms_;
    return true;
}

bool Device::decrypt_transport(const unsigned char* data, std::size_t len) {
    if (len < kTransportHeader + kTag) return false;
    if (rd_le32(data) != kTransport) return false;
    if (rd_le32(data + 4) != local_index_) return false;

    std::uint64_t counter = rd_le64(data + 8);
    std::size_t content_len = len - kTransportHeader - kTag;

    if (counter > recv_counter_) {
        std::uint64_t shift = counter - recv_counter_;
        recv_bitmap_ = (shift >= 64) ? 0 : (recv_bitmap_ << shift);
        recv_counter_ = counter;
    } else {
        std::uint64_t diff = recv_counter_ - counter;
        if (diff >= 64) return false;
        std::uint64_t bit = 1ULL << diff;
        if (recv_bitmap_ & bit) return false;  // replay
        recv_bitmap_ |= bit;
    }

    if (content_len == 0) {
        unsigned char dummy[1];
        if (!aead_open(recv_key_, counter, data + kTransportHeader, 0, nullptr, 0, dummy)) return false;
        rx_bytes_ += len;
        last_rx_ms_ = monotonic_ms();
        return true;  // keepalive
    }

    std::vector<unsigned char> plain(content_len);
    if (!aead_open(recv_key_, counter, data + kTransportHeader, content_len, nullptr, 0, plain.data())) {
        return false;
    }
    rx_bytes_ += len;
    last_rx_ms_ = monotonic_ms();
    if (on_packet_) on_packet_(plain.data(), plain.size());
    return true;
}

void Device::handle_datagram(const unsigned char* data, std::size_t len) {
    if (len < 4) return;
    // A WARP peer may echo the reserved bytes back. Work on a normalised copy
    // so the frame type is a plain opcode again; no recursion, just one hop.
    std::vector<unsigned char> norm;
    const unsigned char* frame = data;
    std::size_t frameLen = len;
    if (has_reserved_) {
        norm.assign(data, data + len);
        strip_reserved(norm.data(), norm.size());
        frame = norm.data();
        frameLen = norm.size();
    }
    // The message type is a little-endian uint32 (WireGuard marshals a uint8 + 3 nul bytes).
    switch (rd_le32(frame)) {
        case kResponse:
            if (awaiting_response_) consume_response(frame, frameLen);
            break;
        case kCookieReply:
            break;  // cookie replies are not required for WARP in practice
        case kTransport:
            if (have_keys_) decrypt_transport(frame, frameLen);
            break;
        default:
            break;
    }
}

bool Device::send_packet(const unsigned char* packet, std::size_t len) {
    if (!have_keys_ || expired() || !send_) return false;

    std::vector<unsigned char> out(kTransportHeader + len + kTag, 0);
    put_le32(out.data(), kTransport);
    put_le32(out.data() + 4, remote_index_);
    put_le64(out.data() + 8, send_counter_);

    if (!aead_seal(send_key_, send_counter_, packet, len, nullptr, 0, out.data() + kTransportHeader)) {
        last_error_ = "AEAD seal failed";
        return false;
    }
    ++send_counter_;
    tx_bytes_ += out.size();
    last_send_ms_ = monotonic_ms();
    if (has_reserved_) apply_reserved(out.data(), out.size(), reserved_);
    return send_(out.data(), out.size());
}

bool Device::expired() const {
    if (!have_keys_) return true;
    return (monotonic_ms() - last_handshake_ms_) > 180000u;
}

void Device::tick() {
    if (!have_keys_) return;
    std::uint32_t now = monotonic_ms();
    if ((now - last_send_ms_) >= static_cast<std::uint32_t>(keepalive_seconds_) * 1000u) {
        send_packet(nullptr, 0);
    }
}

} // namespace bpb::wg
