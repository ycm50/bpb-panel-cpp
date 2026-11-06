#include "inbound/inbound.h"

#include "inbound/proto/grpc.h"
#include "inbound/proto/ws_transport.h"
#include "proxy/session.h"
#include "util/budget.h"
#include "util/log.h"
#include "util/thread.h"
#include "util/util.h"

#include <openssl/ssl.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>

namespace bpb::proxy {

namespace {

using wsx::Addr;
using wsx::Outbound;
using wsx::kChunk;
using wsx::kHandshakeTimeoutMs;
using wsx::kWaitSliceMs;
using wsx::now_ms;

// ---------------------------------------------------------------------------
// VLESS request header, copied from vless_ws.cpp on purpose.
//
// The header is the protocol: version, 16-byte uuid, addons, command, port,
// address. Every transport parses the same bytes, and a shared helper would mean
// that a fix for one transport silently changes what another one accepts. The
// copy is the contract, so the WS implementation can keep evolving without
// touching what ships here.
//
// need_more distinguishes "not enough bytes yet" (a real possibility: the first
// gRPC message may hold only part of the header) from "these bytes are wrong"
// (drop the session).
bool parse_vless(const std::string& buf, const std::string& uuid, Addr& addr,
                 std::size_t& header_len, std::string& response_header, bool& need_more) {
    need_more = false;
    if (buf.size() < 18) {
        need_more = true;
        return false;
    }
    const int version = static_cast<unsigned char>(buf[0]);
    const std::string uuid_bytes = buf.substr(1, 16);
    // The credential IS this 16-byte id: without the comparison this inbound is
    // an open proxy.
    std::string clean;
    clean.reserve(32);
    for (char c : uuid) {
        if (c != '-' && c != ' ') clean.push_back(c);
    }
    if (clean.size() != 32) return false;   // malformed configured uuid: fail closed
    std::string expected;
    expected.reserve(16);
    const auto hex = [](char h) -> int {
        if (h >= '0' && h <= '9') return h - '0';
        if (h >= 'a' && h <= 'f') return h - 'a' + 10;
        if (h >= 'A' && h <= 'F') return h - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0; i + 1 < clean.size(); i += 2) {
        const int hi = hex(clean[i]);
        const int lo = hex(clean[i + 1]);
        if (hi < 0 || lo < 0) return false;
        expected.push_back(static_cast<char>((hi << 4) | lo));
    }
    if (expected != uuid_bytes) return false;

    std::size_t pos = 17;
    const std::size_t addons_len = static_cast<unsigned char>(buf[pos++]);
    if (buf.size() < pos + addons_len + 1) {
        need_more = true;
        return false;
    }
    pos += addons_len;
    const int command = static_cast<unsigned char>(buf[pos++]);
    if (command != 1) return false;   // TCP only
    if (pos + 2 > buf.size()) {
        need_more = true;
        return false;
    }
    if (!wsx::read_port(buf, pos, addr)) return false;
    if (!wsx::parse_atyp_addr(buf, pos, addr)) {
        need_more = addr.need_more;
        return false;
    }
    header_len = pos;

    // The response is version + 0; Xray only checks that something arrived.
    response_header.push_back(static_cast<char>(version));
    response_header.push_back(0);
    return true;
}

// Relays one VLESS session over one gRPC stream. This is vless_ws.cpp's
// session_loop with the WebSocket frame layer replaced by the gRPC byte stream:
// two threads, one per direction, because a single poll loop let one slow
// direction starve the other (see the note in vless_ws.cpp).
void session_loop(std::shared_ptr<grpc::Stream> stream, const SessionConfig& config) {
    Outbound upstream;
    std::string response_header;
    unsigned long long to_upstream = 0;
    unsigned long long to_client = 0;
    std::atomic<const char*> exitReason{"session finished"};
    std::atomic<bool> finished{false};
    std::atomic<bool> upstreamReady{false};
    std::mutex upstreamMutex;
    // Gate for the download thread: it must not read while the upload thread is
    // still parsing the VLESS header and dialling the origin.
    std::mutex gateMutex;
    std::condition_variable gateCv;
    const auto gateOpen = [&] {
        {
            std::lock_guard<std::mutex> lk(gateMutex);
        }
        gateCv.notify_all();
    };

    bool need_more = false;
    const auto try_connect = [&](const std::string& data) -> bool {
        Addr addr;
        std::size_t header_len = 0;
        need_more = false;
        const bool parsed =
            parse_vless(data, config.vl_uuid, addr, header_len, response_header, need_more);
        if (bpb::log::enabled(bpb::log::kTrace)) {
            std::fprintf(stderr, "[grpc] vless parsed=%d header_len=%zu host=%s port=%d first=%zu:",
                         parsed ? 1 : 0, header_len, addr.host.c_str(), addr.port,
                         data.size() < 40 ? data.size() : 40);
            for (std::size_t i = 0; i < data.size() && i < 40; ++i)
                std::fprintf(stderr, " %02x", static_cast<unsigned char>(data[i]));
            std::fputc('\n', stderr);
        }
        if (!parsed) return false;

        Addr target;
        wsx::resolve_target(addr.host, addr.port, config, target);
        upstream = wsx::connect_outbound(target.host, target.port, 8000);
        if (!upstream.valid()) return false;

        // VLESS response, as one gRPC message on the same bidi stream.
        if (!response_header.empty()) {
            if (!stream->write(response_header.data(), response_header.size())) return false;
        }
        if (data.size() > header_len) {
            const std::string rest = data.substr(header_len);
            if (!upstream.write(rest.data(), rest.size())) return false;
        }
        return true;
    };

    // ---- client -> upstream -------------------------------------------------
    // Also owns the VLESS handshake: the target address only becomes known once
    // the first bytes of the stream have arrived.
    bpb::util::Thread toUpstream;
    toUpstream.start([&] {
        char buf[kChunk];
        std::string hasBuf;
        const std::int64_t handshakeDeadline = now_ms() + kHandshakeTimeoutMs;
        try {
            while (!finished.load()) {
                if (!upstreamReady.load()) {
                    if (now_ms() > handshakeDeadline) {
                        exitReason = "handshake timeout";
                        break;
                    }
                    if (!hasBuf.empty()) {
                        bool ok = false;
                        {
                            std::lock_guard<std::mutex> lk(upstreamMutex);
                            ok = try_connect(hasBuf);
                        }
                        if (ok) {
                            hasBuf.clear();
                            upstreamReady.store(true);
                            gateOpen();
                        } else if (!need_more || hasBuf.size() > 8192) {
                            exitReason = "handshake rejected";
                            break;
                        }
                    }
                }
                // poll-bounded read: the slice keeps this thread from spinning
                // while the other direction keeps flowing.
                const int n = stream->read(buf, static_cast<int>(sizeof(buf)), kWaitSliceMs);
                if (n < 0) {
                    exitReason = "client closed";
                    break;
                }
                if (n == 0) continue;
                if (!upstreamReady.load()) {
                    hasBuf.append(buf, static_cast<std::size_t>(n));
                    if (hasBuf.size() > 8192) {
                        exitReason = "handshake buffer overflow";
                        break;
                    }
                    continue;
                }
                if (!upstream.write(buf, static_cast<std::size_t>(n))) {
                    exitReason = "upstream write failed";
                    break;
                }
                to_upstream += static_cast<unsigned long long>(n);
            }
        } catch (...) {
            exitReason = "exception in upload thread";
        }
        finished.store(true);
        gateOpen();
    });

    // ---- upstream -> client -------------------------------------------------
    bpb::util::Thread toClient;
    toClient.start([&] {
        // Grows only after a read that filled it; see util/budget.h.
        bpb::util::RelayBuffer rb;
        try {
            while (!finished.load()) {
                if (!upstreamReady.load()) {
                    std::unique_lock<std::mutex> lk(gateMutex);
                    gateCv.wait_for(lk, std::chrono::milliseconds(kWaitSliceMs),
                                    [&] { return upstreamReady.load() || finished.load(); });
                    continue;
                }
                const int n = upstream.read(rb.data(), static_cast<int>(rb.size()), kWaitSliceMs);
                if (n < 0) {
                    exitReason = "upstream closed";
                    break;
                }
                if (n == 0) continue;
                if (static_cast<std::size_t>(n) == rb.size()) rb.grow();
                if (!stream->write(rb.data(), static_cast<std::size_t>(n))) {
                    exitReason = "client write failed";
                    break;
                }
                to_client += static_cast<unsigned long long>(n);
            }
        } catch (...) {
            exitReason = "exception in download thread";
        }
        finished.store(true);
    });

    toUpstream.join();
    finished.store(true);
    toClient.join();

    if (bpb::log::enabled(bpb::log::kDebug))
        std::fprintf(stderr, "[grpc] session end: up=%llu down=%llu reason=%s path=%s\n", to_upstream,
                     to_client, exitReason.load(), stream->path().c_str());
    upstream.close();
}

} // namespace

// One gRPC stream == one VLESS session. Called from grpc.cpp on the stream's own
// thread; the trailers are sent by the caller once this returns.
namespace grpc {

void vless_grpc_stream(std::shared_ptr<Stream> stream, const SessionConfig& config) {
    session_loop(std::move(stream), config);
}

} // namespace grpc

// The WebSocket dispatcher can route "/vlg" here when a client asks for an
// upgrade on the gRPC path. No supported client does -- gRPC never arrives as a
// WebSocket -- so the connection is refused instead of being half-served.
void vless_grpc_serve(net::socket_t client_fd, SSL* client_ssl, std::string accept_key,
                      std::string path, std::string ws_protocol, SessionConfig config) {
    (void)accept_key;
    (void)path;
    (void)ws_protocol;
    (void)config;
    ::bpb::inbound::reject(client_fd, client_ssl);
}

} // namespace bpb::proxy

// Registered by src/inbound/registry.cpp when -DBPB_INBOUNDS includes vless-grpc.
namespace bpb::inbound {
// extern: a plain const at namespace scope has internal linkage in C++, so
// registry.cpp would not see it.
extern const Inbound vless_grpc_inbound = {"vless-grpc", "vlg", "VLESS (gRPC)",
                                           &::bpb::proxy::vless_grpc_serve};
} // namespace bpb::inbound