#include "inbound/inbound.h"

#include "proxy/session.h"
#include "net/tls.h"
#include "util/log.h"
#include "vmess_aead.h"
#include "ws_transport.h"

#include <openssl/evp.h>
#include <openssl/ssl.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace bpb::proxy {

namespace {

using namespace bpb::proxy::wsx;

// Wire values of protocol.SecurityType (common/protocol/headers.proto). Xray
// rejects UNKNOWN and AUTO on the server side, so a well formed client only ever
// sends one of these two.
constexpr int kSecurityAes128Gcm = 3;
constexpr int kSecurityChachaPoly = 4;

// Request options (common/protocol/headers.go).
constexpr unsigned char kOptionChunkStream = 0x01;
constexpr unsigned char kOptionChunkMasking = 0x04;
constexpr unsigned char kOptionGlobalPadding = 0x08;
constexpr unsigned char kOptionAuthenticatedLength = 0x10;

constexpr int kCommandTcp = 0x01;

// UUID text (32 hex digits, dashes optional) to its 16 raw bytes.
bool uuid_bytes(const std::string& uuid, std::string& out) {
    std::string clean;
    clean.reserve(32);
    for (char c : uuid) {
        if (c == '-') continue;
        clean += c;
    }
    if (clean.size() != 32) return false;
    out.clear();
    out.reserve(16);
    for (std::size_t i = 0; i + 1 < clean.size(); i += 2) {
        const std::string byte = clean.substr(i, 2);
        char* end = nullptr;
        const long v = std::strtol(byte.c_str(), &end, 16);
        if (!end || *end != '\0') return false;
        out.push_back(static_cast<char>(v & 0xFF));
    }
    return true;
}

// protocol.ID.CmdKey(): MD5(uuidBytes || "c48619fe-8f02-49e0-b9e9-edf763e17e21").
bool command_key(const std::string& uuid, std::string& out) {
    std::string raw;
    if (!uuid_bytes(uuid, raw)) return false;
    out = vmess::md5(raw + "c48619fe-8f02-49e0-b9e9-edf763e17e21");
    return out.size() == 16;
}

// GenerateChunkNonce: the low 16 bits of the counter overwrite the first two
// bytes of the IV copy; the AEAD nonce is that prefix, cut to its size.
std::string chunk_nonce(const std::string& base, std::uint16_t count) {
    std::string n = base.substr(0, 12);
    n[0] = static_cast<char>((count >> 8) & 0xFF);
    n[1] = static_cast<char>(count & 0xFF);
    return n;
}

// GenerateChacha20Poly1305Key: md5(key) || md5(md5(key)).
std::string chacha_key(const std::string& key) {
    const std::string first = vmess::md5(key);
    return first + vmess::md5(first);
}

struct Request {
    std::string body_iv;    // requestBodyIV, 16 bytes
    std::string body_key;   // requestBodyKey, 16 bytes
    unsigned char resp_header = 0;
    unsigned char option = 0;
    int padding_len = 0;
    int security = 0;
    int command = 0;
    Addr addr;
    std::size_t consumed = 0;   // bytes of the websocket payload the header used
};

enum class ParseState { Ok, NeedMore, Reject };

// Decodes one VMess AEAD request header out of the front of buf.
//
// Layout, see proxy/vmess/aead/encrypt.go and encoding/server.go:
//   [16 auth id][18 sealed length][8 connection nonce][length+16 sealed header]
// The sealed header carries the body keys, the response-header byte, the option
// bits, the target address, the padding and a FNV-1a checksum over all of it.
ParseState parse_request(const std::string& buf, const std::string& cmd_key, Request& out,
                         std::string& why) {
    if (buf.size() < 16) return ParseState::NeedMore;
    const std::string auth_id = buf.substr(0, 16);

    // The auth id is an AES-128-ECB block: BE64(time) || 4 random || CRC32.IEEE
    // of the first twelve bytes. It doubles as the "user exists" probe.
    const std::string id_key = vmess::kdf16(cmd_key, {"AES Auth ID Encryption"});
    std::string id_plain;
    if (!vmess::aes128_ecb_decrypt_block(id_key, auth_id, id_plain)) {
        why = "auth id decrypt failed";
        return ParseState::Reject;
    }
    if (vmess::read_be32(id_plain.data() + 12) != vmess::crc32_ieee(id_plain.substr(0, 12))) {
        why = "auth id checksum mismatch";
        return ParseState::Reject;
    }
    const std::int64_t stamp = static_cast<std::int64_t>(vmess::read_be64(id_plain.data()));
    const std::int64_t now = static_cast<std::int64_t>(std::time(nullptr));
    if (stamp < 0 || (stamp > now ? stamp - now : now - stamp) > 120) {
        why = "auth id timestamp outside 120s";
        return ParseState::Reject;
    }

    if (buf.size() < 42) return ParseState::NeedMore;
    const std::string nonce = buf.substr(34, 8);

    vmess::Gcm length_gcm;
    if (!length_gcm.init(EVP_aes_128_gcm(),
                         vmess::kdf16(cmd_key, {"VMess Header AEAD Key_Length", auth_id, nonce}))) {
        why = "length key";
        return ParseState::Reject;
    }
    const std::string length_iv =
        vmess::kdf(cmd_key, {"VMess Header AEAD Nonce_Length", auth_id, nonce}).substr(0, 12);
    std::string length_plain;
    if (!length_gcm.open(length_iv, auth_id, buf.substr(16, 18), length_plain) ||
        length_plain.size() != 2) {
        why = "header length authenticate";
        return ParseState::Reject;
    }
    const std::uint16_t header_len = vmess::read_be16(length_plain.data());
    const std::size_t total = 42 + static_cast<std::size_t>(header_len) + 16;
    if (buf.size() < total) return ParseState::NeedMore;

    vmess::Gcm payload_gcm;
    if (!payload_gcm.init(EVP_aes_128_gcm(),
                          vmess::kdf16(cmd_key, {"VMess Header AEAD Key", auth_id, nonce}))) {
        why = "header key";
        return ParseState::Reject;
    }
    const std::string payload_iv =
        vmess::kdf(cmd_key, {"VMess Header AEAD Nonce", auth_id, nonce}).substr(0, 12);
    std::string header;
    if (!payload_gcm.open(payload_iv, auth_id, buf.substr(42, header_len + 16), header)) {
        why = "header authenticate";
        return ParseState::Reject;
    }
    if (header.size() < 38) {
        why = "header too short";
        return ParseState::Reject;
    }

    out.body_iv = header.substr(1, 16);
    out.body_key = header.substr(17, 16);
    out.resp_header = static_cast<unsigned char>(header[33]);
    out.option = static_cast<unsigned char>(header[34]);
    out.padding_len = static_cast<unsigned char>(header[35]) >> 4;
    out.security = static_cast<unsigned char>(header[35]) & 0x0F;
    if (header[36] != 0) {
        why = "reserved byte not zero";
        return ParseState::Reject;
    }
    out.command = static_cast<unsigned char>(header[37]);

    if (out.command != kCommandTcp) {
        // UDP needs the packet framing, mux needs v1.mux.cool; neither is served
        // by a TCP relay, so say so instead of pretending to.
        why = "unsupported command " + std::to_string(out.command);
        return ParseState::Reject;
    }

    // encoding/encoding.go builds the VMess address parser with
    // protocol.PortThenAddress(), unlike VLESS/Trojan which put the port last.
    std::size_t pos = 38;
    Addr addr;
    if (!read_port(header, pos, addr)) {
        why = "port parse";
        return ParseState::Reject;
    }
    if (!parse_atyp_addr(header, pos, addr)) {
        why = "address parse";
        return ParseState::Reject;
    }
    const std::size_t used = pos + static_cast<std::size_t>(out.padding_len);
    if (header.size() != used + 4) {
        why = "header length mismatch";
        return ParseState::Reject;
    }
    if (vmess::fnv1a32(header.substr(0, used)) != vmess::read_be32(header.data() + used)) {
        why = "header checksum";
        return ParseState::Reject;
    }

    out.addr = addr;
    out.consumed = total;
    return ParseState::Ok;
}

// Client -> origin. Mirrors crypto.AuthenticationReader: every chunk is
// [size][AEAD payload][cleartext padding], the size is masked with a SHAKE128
// stream seeded from requestBodyIV and the chunk nonce counts up from zero.
class Decoder {
public:
    bool init(const Request& req, std::string& why) {
        req_ = req;
        chunked_ = (req.option & kOptionChunkStream) != 0;
        masked_ = (req.option & kOptionChunkMasking) != 0;
        padded_ = (req.option & kOptionGlobalPadding) != 0;
        auth_len_ = (req.option & kOptionAuthenticatedLength) != 0;
        nonce_base_ = req.body_iv;
        if (!chunked_) return true;
        if (auth_len_ && padded_) {
            // Xray cannot express this either: the padding generator is the size
            // parser, and AEADSizeParser is not one.
            why = "authenticated length together with padding";
            return false;
        }
        std::string key = req.body_key;
        const EVP_CIPHER* cipher = EVP_aes_128_gcm();
        if (req.security == kSecurityChachaPoly) {
            key = chacha_key(key);
            cipher = EVP_chacha20_poly1305();
        } else if (req.security != kSecurityAes128Gcm) {
            why = "unsupported security " + std::to_string(req.security);
            return false;
        }
        if (!body_.init(cipher, key)) {
            why = "body key";
            return false;
        }
        if (masked_ || padded_) shake_.reset(new vmess::Shake128(req.body_iv));
        if (auth_len_) {
            if (!length_.init(EVP_aes_128_gcm(), vmess::kdf16(req.body_key, {"auth_len"}))) {
                why = "auth_len key";
                return false;
            }
        }
        return true;
    }

    // Appends every complete chunk's plaintext to out. eof is set once the
    // termination chunk (an empty payload) arrives.
    bool feed(const char* data, std::size_t len, std::string& out, bool& eof, std::string& why) {
        if (!chunked_) {
            out.append(data, len);
            return true;
        }
        buf_.append(data, len);
        while (true) {
            if (eof_) {
                eof = true;
                return true;
            }
            if (!have_size_) {
                const std::size_t size_bytes = auth_len_ ? 18 : 2;
                if (buf_.size() < size_bytes) return true;
                const std::uint16_t padding = padded_ ? shake_->next_padding() : 0;
                const std::string block = buf_.substr(0, size_bytes);
                buf_.erase(0, size_bytes);
                std::uint16_t raw = vmess::read_be16(block.data());
                if (auth_len_) {
                    std::string plain;
                    if (!length_.open(chunk_nonce(req_.body_iv, length_count_++), "", block, plain) ||
                        plain.size() != 2) {
                        why = "chunk length authenticate";
                        return false;
                    }
                    raw = static_cast<std::uint16_t>(vmess::read_be16(plain.data()) + 16);
                } else if (masked_) {
                    raw = static_cast<std::uint16_t>(raw ^ shake_->next());
                }
                size_ = raw;
                padding_ = padding;
                have_size_ = true;
            }
            if (size_ == static_cast<std::uint16_t>(16 + padding_)) {
                eof_ = true;
                eof = true;
                return true;
            }
            if (size_ < padding_) {
                why = "chunk shorter than its padding";
                return false;
            }
            if (buf_.size() < size_) return true;
            const std::string chunk = buf_.substr(0, size_ - padding_);
            buf_.erase(0, size_);
            have_size_ = false;
            std::string plain;
            if (!body_.open(chunk_nonce(nonce_base_, count_++), "", chunk, plain)) {
                why = "chunk authenticate";
                return false;
            }
            out += plain;
        }
    }

private:
    Request req_;
    bool chunked_ = true, masked_ = false, padded_ = false, auth_len_ = false;
    bool have_size_ = false, eof_ = false;
    std::uint16_t size_ = 0, padding_ = 0;
    std::uint16_t count_ = 0, length_count_ = 0;
    std::string nonce_base_;
    std::string buf_;
    vmess::Gcm body_, length_;
    std::unique_ptr<vmess::Shake128> shake_;
};

// Origin -> client. Mirrors crypto.AuthenticationWriter, including its quirk of
// deriving the response body keys as SHA256 of the request ones.
class Encoder {
public:
    bool init(const Request& req, std::string& why) {
        req_ = req;
        chunked_ = (req.option & kOptionChunkStream) != 0;
        masked_ = (req.option & kOptionChunkMasking) != 0;
        padded_ = (req.option & kOptionGlobalPadding) != 0;
        auth_len_ = (req.option & kOptionAuthenticatedLength) != 0;
        body_iv_ = vmess::sha256(req.body_iv).substr(0, 16);
        body_key_ = vmess::sha256(req.body_key).substr(0, 16);
        if (!chunked_) return true;
        if (auth_len_ && padded_) {
            why = "authenticated length together with padding";
            return false;
        }
        std::string key = body_key_;
        const EVP_CIPHER* cipher = EVP_aes_128_gcm();
        if (req.security == kSecurityChachaPoly) {
            key = chacha_key(key);
            cipher = EVP_chacha20_poly1305();
        } else if (req.security != kSecurityAes128Gcm) {
            why = "unsupported security " + std::to_string(req.security);
            return false;
        }
        if (!body_.init(cipher, key)) {
            why = "response body key";
            return false;
        }
        if (masked_ || padded_) shake_.reset(new vmess::Shake128(body_iv_));
        if (auth_len_) {
            // Bug compatible with encoding/server.go: the response's length
            // authenticator reuses the *request* key and IV.
            if (!length_.init(EVP_aes_128_gcm(), vmess::kdf16(req.body_key, {"auth_len"}))) {
                why = "auth_len key";
                return false;
            }
        }
        return true;
    }

    // Response header block: sealed length + sealed payload.
    std::string header() {
        // Four bytes, not two: the client reads responseHeader, option, then the
        // command id and its length (MarshalCommand(nil) writes 0x00 0x00), and
        // a short payload makes it fail with "unexpected EOF".
        std::string payload(4, '\0');
        payload[0] = static_cast<char>(req_.resp_header);
        vmess::Gcm length_gcm;
        length_gcm.init(EVP_aes_128_gcm(), vmess::kdf16(body_key_, {"AEAD Resp Header Len Key"}));
        const std::string length_iv =
            vmess::kdf(body_iv_, {"AEAD Resp Header Len IV"}).substr(0, 12);
        std::string sealed_length;
        length_gcm.seal(length_iv, "", vmess::be16(static_cast<std::uint16_t>(payload.size())),
                        sealed_length);

        vmess::Gcm payload_gcm;
        payload_gcm.init(EVP_aes_128_gcm(), vmess::kdf16(body_key_, {"AEAD Resp Header Key"}));
        const std::string payload_iv =
            vmess::kdf(body_iv_, {"AEAD Resp Header IV"}).substr(0, 12);
        std::string sealed_payload;
        payload_gcm.seal(payload_iv, "", payload, sealed_payload);
        return sealed_length + sealed_payload;
    }

    // Largest plaintext a single chunk can carry.
    static constexpr std::size_t kMaxPayload = 8192;

    std::string seal(const char* data, std::size_t len) {
        if (!chunked_) return std::string(data, len);
        const std::uint16_t padding = padded_ ? shake_->next_padding() : 0;
        std::string sealed;
        body_.seal(chunk_nonce(body_iv_, count_++), "", std::string(data, len), sealed);
        const std::uint16_t total =
            static_cast<std::uint16_t>(sealed.size() + padding);
        std::string out;
        if (auth_len_) {
            std::string length_block;
            length_.seal(chunk_nonce(req_.body_iv, length_count_++), "",
                         vmess::be16(static_cast<std::uint16_t>(total - 16)), length_block);
            out += length_block;
        } else {
            std::uint16_t masked_total = total;
            if (masked_) masked_total = static_cast<std::uint16_t>(masked_total ^ shake_->next());
            out += vmess::be16(masked_total);
        }
        out += sealed;
        if (padding) {
            // Cleartext padding, so the wire signature does not depend on the
            // plaintext length.
            std::string pad(padding, '\0');
            for (char& c : pad) c = static_cast<char>(std::rand() & 0xFF);
            out += pad;
        }
        return out;
    }

    // Termination chunk: an AEAD-sealed empty payload. Without it the client
    // reports the response body as truncated.
    std::string finish() { return seal("", 0); }

    bool chunked() const { return chunked_; }

private:
    Request req_;
    bool chunked_ = true, masked_ = false, padded_ = false, auth_len_ = false;
    std::uint16_t count_ = 0, length_count_ = 0;
    std::string body_iv_, body_key_;
    vmess::Gcm body_, length_;
    std::unique_ptr<vmess::Shake128> shake_;
};

// One websocket session. Two threads, one per direction, exactly like the other
// protocol implementations: a single poll loop starves one direction as soon as
// the other blocks for a moment, which is what produces the stalled downloads.
void session_loop(SSL* client_ssl, socket_t client, const SessionConfig& config, std::string early) {
    std::string cmd_key;
    if (!command_key(config.vl_uuid, cmd_key)) {
        bpb::log::error("[vmess] refusing: the configured UUID is not a valid uuid");
        if (client_ssl) {
            SSL_shutdown(client_ssl);
            net::tls_free(client_ssl);
        }
        net::close(client);
        return;
    }

    std::atomic<bool> finished{false};
    std::atomic<bool> upstream_ready{false};
    std::atomic<bool> finished_flag{false};   // termination chunk already sent
    std::atomic<const char*> exit_reason{"session finished"};
    std::mutex write_mutex;   // serialises websocket writes from both threads
    std::mutex upstream_mutex;
    Outbound upstream;
    std::unique_ptr<Encoder> encoder;
    unsigned long long to_upstream = 0;
    unsigned long long to_client = 0;

    auto client_write = [&](const char* data, std::size_t len) {
        std::lock_guard<std::mutex> lock(write_mutex);
        return ws_send(client_ssl, client, data, len);
    };

    // ---- client -> origin --------------------------------------------------
    std::thread up([&] {
        Request req;
        Decoder decoder;
        Encoder enc;
        bool header_done = false;
        bool request_done = false;
        std::string stash = early;
        std::string pending;

        // Returns 1 when the handshake completed, 0 when more bytes are needed and
        // -1 when the request has to be dropped.
        auto attempt_header = [&]() -> int {
            std::string why;
            ParseState ps = parse_request(stash, cmd_key, req, why);
            if (ps == ParseState::NeedMore) {
                if (stash.size() > 16384) {
                    bpb::log::debug("[vmess] header never completed (%zu bytes)", stash.size());
                    exit_reason = "header too large";
                    return -1;
                }
                return 0;
            }
            if (ps == ParseState::Reject) {
                bpb::log::debug("[vmess] request rejected: %s", why.c_str());
                exit_reason = "handshake rejected";
                return -1;
            }
            stash.erase(0, req.consumed);
            if (!decoder.init(req, why) || !enc.init(req, why)) {
                bpb::log::debug("[vmess] session setup failed: %s", why.c_str());
                exit_reason = "session setup";
                return -1;
            }

            Addr target;
            resolve_target(req.addr.host, req.addr.port, config, target);
            {
                std::lock_guard<std::mutex> lock(upstream_mutex);
                upstream = connect_outbound(target.host, target.port, 8000);
            }
            if (!upstream.valid()) {
                bpb::log::debug("[vmess] cannot connect %s:%d", target.host.c_str(), target.port);
                exit_reason = "origin connect failed";
                return -1;
            }
            // The response header must reach the client before the first body
            // chunk, so it is written here and upstream_ready is published only
            // afterwards.
            const std::string head = enc.header();
            if (bpb::log::enabled(bpb::log::kTrace))
                bpb::log::debug("[vmess] resp_head(%zu)=%s", head.size(),
                                vmess::hex(head).c_str());
            if (!client_write(head.data(), head.size())) {
                exit_reason = "client write failed";
                return -1;
            }
            encoder.reset(new Encoder(std::move(enc)));
            header_done = true;
            upstream_ready.store(true);
            if (bpb::log::enabled(bpb::log::kDebug))
                bpb::log::debug("[vmess] %s:%d security=%d option=0x%02x padding=%d",
                                req.addr.host.c_str(), req.addr.port, req.security, req.option,
                                req.padding_len);
            return 1;
        };

        // Decodes whatever is buffered and hands it to the origin.
        auto forward = [&]() -> bool {
            std::string plain;
            bool eof = false;
            std::string why;
            if (!decoder.feed(stash.data(), stash.size(), plain, eof, why)) {
                bpb::log::debug("[vmess] upload decode failed: %s", why.c_str());
                exit_reason = "upstream frame error";
                return false;
            }
            stash.clear();
            if (!plain.empty()) {
                if (!upstream.write(plain.data(), plain.size())) {
                    exit_reason = "upstream write failed";
                    return false;
                }
                to_upstream += plain.size();
            }
            if (eof) {
                // The client finished its request; the response may still be
                // streaming. Keep reading frames so a client close is still
                // noticed, but stop forwarding (ending the session here used to
                // truncate every download).
                bpb::log::debug("[vmess] request body finished");
                request_done = true;
            }
            return true;
        };

        try {
            while (!finished.load()) {
                // The upgrade request itself can carry the first bytes: with
                // early data enabled the client puts the whole VMess header in
                // Sec-WebSocket-Protocol and then waits for the response, so the
                // handshake has to be attempted from the buffer BEFORE reading a
                // frame. Waiting for a frame first deadlocked every early-data
                // session.
                if (!header_done && !stash.empty()) {
                    const int hr = attempt_header();
                    if (hr < 0) break;
                    if (hr > 0) {
                        if (!forward()) break;
                        continue;
                    }
                }

                std::string payload;
                int opcode = 0;
                FrameState st = read_frame(client_ssl, client, pending, payload, opcode);
                if (st == FrameState::NeedMore) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }
                if (st != FrameState::Ok) {
                    exit_reason = (st == FrameState::Closed) ? "client closed" : "client frame error";
                    break;
                }
                if (opcode == 0x8) { exit_reason = "ws close frame"; break; }
                if (opcode == 0x9) {
                    {
                        std::lock_guard<std::mutex> lock(write_mutex);
                        ws_send(client_ssl, client, payload.data(), payload.size(), 0xA);
                    }
                    continue;
                }
                if (opcode == 0xA) continue;

                if (!header_done) {
                    stash += payload;
                    continue;   // the next iteration tries the handshake again
                }
                stash = std::move(payload);
                if (request_done || stash.empty()) continue;
                if (!forward()) break;
            }
        } catch (...) {
            exit_reason = "exception in upload thread";
        }
        finished.store(true);
    });

    // ---- origin -> client --------------------------------------------------
    std::thread down([&] {
        try {
            while (!finished.load()) {
                if (!upstream_ready.load()) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                    continue;
                }
                char buf[kChunk];
                int n = upstream.read(buf, sizeof(buf), 100);
                if (n < 0) {
                    // Origin done: seal the response with the termination chunk so
                    // the client sees a clean end rather than a truncated body.
                    Encoder* enc = encoder.get();
                    if (enc) {
                        const std::string tail = enc->finish();
                        client_write(tail.data(), tail.size());
                        finished_flag = true;
                    }
                    exit_reason = "upstream closed";
                    break;
                }
                if (n == 0) continue;
                Encoder* enc = encoder.get();
                if (!enc) break;
                std::size_t off = 0;
                while (off < static_cast<std::size_t>(n)) {
                    const std::size_t take = std::min<std::size_t>(Encoder::kMaxPayload,
                                                                   static_cast<std::size_t>(n) - off);
                    const std::string chunk = enc->seal(buf + off, take);
                    if (!client_write(chunk.data(), chunk.size())) {
                        exit_reason = "client write failed";
                        finished.store(true);
                        return;
                    }
                    off += take;
                }
                to_client += static_cast<unsigned long long>(n);
            }
        } catch (...) {
            exit_reason = "exception in download thread";
        }
        finished.store(true);
    });

    up.join();
    down.join();

    // Termination chunk, then the websocket close frame. Skipping the former
    // makes the client log a truncated response. The download thread already
    // sent it when the origin closed, so only send it for the other exits.
    if (encoder && !finished_flag.load()) {
        const std::string tail = encoder->finish();
        client_write(tail.data(), tail.size());
    }
    if (bpb::log::enabled(bpb::log::kDebug))
        bpb::log::debug("[vmess] session end: up=%llu down=%llu reason=%s", to_upstream, to_client,
                        exit_reason.load());

    upstream.close();
    {
        const unsigned char close_frame[4] = {0x88, 0x02, 0x03, 0xE8};
        std::lock_guard<std::mutex> lock(write_mutex);
        send_all(client_ssl, client, reinterpret_cast<const char*>(close_frame), sizeof(close_frame));
    }
    if (client_ssl) {
        SSL_shutdown(client_ssl);
        net::tls_free(client_ssl);
    }
    if (client != net::kInvalid) net::close(client);
}

} // namespace

// Entry point: the dispatcher has already matched the "<uuid>-vm" segment.
void vmess_serve(net::socket_t client_fd, SSL* client_ssl, std::string accept_key, std::string path,
                 std::string ws_protocol, SessionConfig config) {
    std::string early = ws_protocol.empty() ? std::string() : decode_early_data(ws_protocol);
    if (bpb::log::enabled(bpb::log::kTrace))
        bpb::log::debug("[vmess] upgrade path=%s wsproto=%zu early=%zu", path.c_str(),
                        ws_protocol.size(), early.size());
    std::string response = "HTTP/1.1 101 Switching Protocols\r\n"
                           "Upgrade: websocket\r\n"
                           "Connection: Upgrade\r\n";
    if (!accept_key.empty()) response += "Sec-WebSocket-Accept: " + accept_key + "\r\n";
    if (!early.empty()) response += "Sec-WebSocket-Protocol: " + ws_protocol + "\r\n";
    response += "\r\n";
    if (!send_all(client_ssl, client_fd, response.data(), response.size())) {
        if (client_ssl) net::tls_free(client_ssl);
        net::close(client_fd);
        return;
    }
    std::thread([client_fd, client_ssl, config, early]() {
        session_loop(client_ssl, client_fd, config, early);
    }).detach();
}

} // namespace bpb::proxy

namespace bpb::inbound {

namespace {

// VMess derives its websocket path from the credential: the client is told to
// use "/<uuid>-vm", so the segment cannot be a compile-time constant.
bool vmess_match(std::string_view segment, const bpb::proxy::SessionConfig& config) {
    if (config.vl_uuid.empty()) return false;
    std::string clean;
    for (char c : config.vl_uuid) {
        if (c != '-') clean += c;
    }
    const std::string dashed = config.vl_uuid;
    return segment == clean + "-vm" || segment == dashed + "-vm";
}

} // namespace

// Registered by src/inbound/registry.cpp when -DBPB_INBOUNDS includes vmess.
// extern: a plain const at namespace scope has internal linkage in C++.
extern const Inbound vmess_inbound = {"vmess", nullptr, "VMess", &::bpb::proxy::vmess_serve,
                                      &vmess_match};

} // namespace bpb::inbound
