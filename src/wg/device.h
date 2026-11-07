#pragma once
#include "wg/crypto.h"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace bpb::wg {

using SendFn = std::function<bool(const unsigned char*, std::size_t)>;
using PacketFn = std::function<void(const unsigned char*, std::size_t)>;

struct PeerConfig {
    std::string private_key_b64;
    std::string peer_public_b64;
    std::string local_ipv4;
    std::string local_ipv6;
    int mtu = 1280;
    int keepalive_seconds = 25;
    // WARP account discriminator (the first three bytes of the registration
    // client_id). Xray-core's WARP bind overwrites packet bytes 1..3 with these
    // on send and zeroes them again on receive -- see proxy/wireguard/bind.go.
    // Zero means "plain WireGuard", which is what a self-hosted peer expects.
    unsigned char reserved[3] = {0, 0, 0};
    bool has_reserved = false;
};

// Userspace WireGuard initiator: Noise_IKpsk2 handshake + ChaCha20-Poly1305 transport.
class Device {
public:
    Device() = default;

    bool configure(const PeerConfig& cfg, std::string& error);
    void set_send(SendFn fn) { send_ = std::move(fn); }
    void set_on_packet(PacketFn fn) { on_packet_ = std::move(fn); }

    // Sends a handshake initiation and waits for the response to be fed back in.
    bool initiate(std::string& error);
    // Feeds one received UDP datagram through the state machine.
    void handle_datagram(const unsigned char* data, std::size_t len);
    // Encrypts and sends one IP packet (nullptr/0 sends a keepalive).
    bool send_packet(const unsigned char* packet, std::size_t len);
    // Keepalive timer; call periodically.
    void tick();

    bool has_session() const { return have_keys_; }
    bool expired() const;
    std::uint32_t last_handshake_ms() const { return last_handshake_ms_; }
    // Timestamp of the last authenticated packet from the peer (handshake or
    // transport). A peer that silently stops answering - Cloudflare's WARP does
    // this when it invalidates a session - leaves have_keys_ true forever, so
    // the caller needs this to notice the silence and force a new handshake.
    std::uint32_t last_rx_ms() const { return last_rx_ms_; }
    // Drops the transport session so the next initiate() performs a full
    // handshake. Used by the rx-stall watchdog.
    void reset_session() {
        have_keys_ = false;
        awaiting_response_ = false;
    }
    unsigned long long rx_bytes() const { return rx_bytes_; }
    unsigned long long tx_bytes() const { return tx_bytes_; }
    std::string last_error() const { return last_error_; }

    std::uint32_t local_v4() const { return local_v4_; }
    const unsigned char* local_v6() const { return local_v6_; }
    int mtu() const { return mtu_; }

private:
    bool build_initiation(std::string& error);
    bool consume_response(const unsigned char* data, std::size_t len);
    bool decrypt_transport(const unsigned char* data, std::size_t len);

    SendFn send_;
    PacketFn on_packet_;

    unsigned char static_priv_[32]{};
    unsigned char static_pub_[32]{};
    unsigned char peer_pub_[32]{};

    // handshake transcript
    unsigned char hash_[32]{};
    unsigned char chain_key_[32]{};
    unsigned char ephemeral_priv_[32]{};
    unsigned char ephemeral_pub_[32]{};
    std::uint32_t local_index_ = 0;
    std::uint32_t remote_index_ = 0;
    bool awaiting_response_ = false;

    // transport session
    bool have_keys_ = false;
    unsigned char send_key_[32]{};
    unsigned char recv_key_[32]{};
    std::uint64_t send_counter_ = 0;
    std::uint64_t recv_counter_ = 0;
    std::uint64_t recv_bitmap_ = 0;

    std::uint32_t local_v4_ = 0;
    unsigned char local_v6_[16]{};
    int mtu_ = 1280;
    int keepalive_seconds_ = 25;
    unsigned char reserved_[3] = {0, 0, 0};
    bool has_reserved_ = false;

    std::uint32_t last_handshake_ms_ = 0;
    std::uint32_t last_send_ms_ = 0;
    std::uint32_t last_initiate_ms_ = 0;
    std::uint32_t last_rx_ms_ = 0;

    unsigned long long rx_bytes_ = 0;
    unsigned long long tx_bytes_ = 0;
    std::string last_error_;
};

} // namespace bpb::wg
