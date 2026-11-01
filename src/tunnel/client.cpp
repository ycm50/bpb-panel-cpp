#include "tunnel/client.h"
#include "util/log.h"

#include "tunnel/capnp.h"
#include "tunnel/h2.h"
#include "tunnel/ingress.h"
#include "tunnel/proxy.h"
#include "tunnel/rpc.h"

#include <poll.h>
#include <sys/socket.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <sstream>
#include <vector>

namespace bpb::tunnel {

namespace {

std::string b64decode(const std::string& in) {
    static const char* tbl =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int rev[256];
    for (int i = 0; i < 256; ++i) rev[i] = -1;
    for (int i = 0; i < 64; ++i) rev[static_cast<unsigned char>(tbl[i])] = i;
    std::string out;
    int buf = 0, bits = 0;
    for (char ch : in) {
        if (ch == '=' || ch == '\n' || ch == '\r') continue;
        int v = rev[static_cast<unsigned char>(ch)];
        if (v < 0) continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((buf >> bits) & 0xFF));
        }
    }
    return out;
}

std::string json_str(const std::string& json, const char* key) {
    const std::string pat = std::string("\"") + key + "\":\"";
    auto p = json.find(pat);
    if (p == std::string::npos) return {};
    p += pat.size();
    auto e = json.find('"', p);
    return e == std::string::npos ? std::string{} : json.substr(p, e - p);
}

std::vector<std::uint8_t> uuid_to_bytes(const std::string& s) {
    std::vector<std::uint8_t> out;
    unsigned hi = 0;
    int nib = 0;
    for (char c : s) {
        int v = -1;
        if (c >= '0' && c <= '9') v = c - '0';
        else if (c >= 'a' && c <= 'f') v = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') v = c - 'A' + 10;
        if (v < 0) continue;
        hi = (hi << 4) | static_cast<unsigned>(v);
        if (++nib == 2) {
            out.push_back(static_cast<std::uint8_t>(hi));
            hi = 0;
            nib = 0;
        }
    }
    return out;
}

// Splits a raw byte stream into capnp messages. The framing is:
//   (segCount-1) x uint32  segment sizes in words, then padding to a word
//   boundary, then the segment bodies.
// Multi-segment messages are legitimate and the edge does emit them, so the
// whole table must be walked; bailing out on segCount != 0 silently dropped
// every such message and made registration time out.
std::vector<std::pair<std::size_t, std::size_t>> split_messages(const std::vector<std::uint8_t>& b,
                                                               std::size_t from) {
    std::vector<std::pair<std::size_t, std::size_t>> out;
    std::size_t off = from;
    while (off + 4 <= b.size()) {
        std::uint32_t segCount =
            static_cast<std::uint32_t>(b[off]) | (static_cast<std::uint32_t>(b[off + 1]) << 8) |
            (static_cast<std::uint32_t>(b[off + 2]) << 16) |
            (static_cast<std::uint32_t>(b[off + 3]) << 24);
        const std::uint64_t segments = static_cast<std::uint64_t>(segCount) + 1;
        if (segments > 512) break;  // not a plausible capnp header
        // segCount holds (segment count - 1); that many+1 32-bit sizes follow
        // the count word and start at off+4. The whole header -- count plus
        // sizes -- is padded up to an 8-byte boundary. Reading the sizes from
        // off itself silently collapsed every message into an 8-byte stub.
        const std::size_t headerBytes = 4 + 4 * static_cast<std::size_t>(segments);
        const std::size_t padded = (headerBytes + 7) & ~static_cast<std::size_t>(7);
        if (off + padded > b.size()) break;
        std::size_t bodyBytes = 0;
        bool complete = true;
        for (std::uint64_t s = 0; s < segments; ++s) {
            const std::size_t at = off + 4 + 4 * static_cast<std::size_t>(s);
            const std::uint32_t words = static_cast<std::uint32_t>(b[at]) |
                                        (static_cast<std::uint32_t>(b[at + 1]) << 8) |
                                        (static_cast<std::uint32_t>(b[at + 2]) << 16) |
                                        (static_cast<std::uint32_t>(b[at + 3]) << 24);
            bodyBytes += static_cast<std::size_t>(words) * 8;
            if (bodyBytes > 64u * 1024 * 1024) { complete = false; break; }
        }
        if (!complete) break;
        const std::size_t len = padded + bodyBytes;
        if (off + len > b.size()) break;  // wait for the rest
        out.emplace_back(off, len);
        off += len;
    }
    return out;
}

} // namespace

bool TunnelClient::parse_token(const std::string& token, TunnelConfig& out, std::string& error) {
    const std::string json = b64decode(token);
    if (json.empty()) {
        error = "token is not valid base64";
        return false;
    }
    out.accountTag = json_str(json, "a");
    out.tunnelId = json_str(json, "t");
    const std::string secB64 = json_str(json, "s");
    out.tunnelSecret = b64decode(secB64);
    if (out.accountTag.empty() || out.tunnelId.empty() || out.tunnelSecret.empty()) {
        error = "token missing a/t/s fields";
        return false;
    }
    return true;
}

// ---- cloudflared header serialization (connection/header.go) ----------------
// User headers travel inside one h2 header, base64 (RawStd) encoded as
//   b64(name):b64(value);b64(name):b64(value)
// The WebSocket handshake headers are the exception: they must be real h2
// headers or the client never completes the upgrade. HTTP/2 also forbids 101,
// so the edge expects 200 with the upgrade carried in those three headers.
namespace {

std::string b64_raw_encode(const std::string& in) {
    static const char* tbl =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    std::size_t i = 0;
    while (i + 2 < in.size()) {
        unsigned v = (static_cast<unsigned char>(in[i]) << 16) |
                     (static_cast<unsigned char>(in[i + 1]) << 8) |
                     static_cast<unsigned char>(in[i + 2]);
        out.push_back(tbl[(v >> 18) & 0x3F]);
        out.push_back(tbl[(v >> 12) & 0x3F]);
        out.push_back(tbl[(v >> 6) & 0x3F]);
        out.push_back(tbl[v & 0x3F]);
        i += 3;
    }
    if (i < in.size()) {
        unsigned v = static_cast<unsigned char>(in[i]) << 16;
        bool two = (i + 1 < in.size());
        if (two) v |= static_cast<unsigned char>(in[i + 1]) << 8;
        out.push_back(tbl[(v >> 18) & 0x3F]);
        out.push_back(tbl[(v >> 12) & 0x3F]);
        if (two) out.push_back(tbl[(v >> 6) & 0x3F]);
    }
    return out;
}

bool is_websocket_client_header(const std::string& name) {
    return name == "sec-websocket-accept" || name == "connection" || name == "upgrade" ||
           // Xray echoes Sec-WebSocket-Protocol on the 101 to acknowledge early
           // data (transport/internet/websocket/hub.go). cloudflared's helper
           // predates that scheme and omits it, so failing to surface it here
           // makes every Xray client believe its early data was ignored.
           name == "sec-websocket-protocol";
}

std::string b64_raw_decode(const std::string& in) {
    static const char* tbl =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int rev[256];
    for (int i = 0; i < 256; ++i) rev[i] = -1;
    for (int i = 0; i < 64; ++i) rev[static_cast<unsigned char>(tbl[i])] = i;
    std::string out;
    int buf = 0, bits = 0;
    for (char ch : in) {
        int v = rev[static_cast<unsigned char>(ch)];
        if (v < 0) continue;
        buf = (buf << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((buf >> bits) & 0xFF));
        }
    }
    return out;
}

// Parses "b64(name):b64(value);..." into plain header pairs.
void deserialize_user_headers(const std::string& in,
                              std::vector<std::pair<std::string, std::string>>& out) {
    std::size_t start = 0;
    while (start <= in.size()) {
        std::size_t semi = in.find(';', start);
        std::string pair = in.substr(start, semi == std::string::npos ? std::string::npos
                                                                     : semi - start);
        if (!pair.empty()) {
            auto colon = pair.find(':');
            if (colon != std::string::npos) {
                out.emplace_back(b64_raw_decode(pair.substr(0, colon)),
                                 b64_raw_decode(pair.substr(colon + 1)));
            }
        }
        if (semi == std::string::npos) break;
        start = semi + 1;
    }
}

std::string serialize_user_headers(
    const std::vector<std::pair<std::string, std::string>>& headers) {
    std::string out;
    for (auto& kv : headers) {
        if (!out.empty()) out.push_back(';');
        out += b64_raw_encode(kv.first);
        out.push_back(':');
        out += b64_raw_encode(kv.second);
    }
    return out;
}

// RFC 6455 5.5.1: a close frame is opcode 0x8 with an empty payload. The origin
// expects one when the eyeball goes away, otherwise it holds the TCP session
// open until its own idle timeout.
void send_ws_close(const std::shared_ptr<OriginStream>& origin) {
    if (!origin || !origin->valid()) return;
    const std::uint8_t frame[2] = {0x88, 0x00};
    origin->write(frame, sizeof(frame));
    origin->flush();
}

} // namespace

bool TunnelClient::run(const TunnelConfig& cfg, TunnelStatus& status,
                       const std::function<void(const std::string&)>& log,
                       const std::function<void(const TunnelStatus&)>& on_status) {
    auto L = [&](const std::string& s) { if (log) log(s); };
    // Every narration goes through the log switch (off unless BPB_LOG/--log asks
    // for it). L is errors only; these two are the noisy tiers.
    auto LI = [&](const std::string& s) { if (bpb::log::enabled(bpb::log::kInfo)) L(s); };
    auto LD = [&](const std::string& s) { if (bpb::log::enabled(bpb::log::kDebug)) L(s); };
    // Pushes the live status out. Without this the panel only ever saw the
    // snapshot taken right after the first attempt, which is before the edge
    // accepts the registration, so a healthy tunnel displayed "not connected".
    auto publish = [&]() { if (on_status) on_status(status); };

    // Per-stream request accumulation.
    struct StreamCtx {
        std::string method;
        std::string path;
        std::map<std::string, std::string> headers;
        bool isControl = false;
        bool isConfig = false;     // edge-pushed ingress configuration
        std::string configBody;
        // END_STREAM seen for this stream. The configuration update arrives as
        // HEADERS followed by DATA, and the HEADERS frame carries END_STREAM
        // only for the (empty) control dialogue; acking on the HEADERS frame
        // dropped the body before the edge sent it, which is why the ingress
        // hostnames used to come back empty.
        bool endSeen = false;
        bool responded = false;    // origin head already relayed
        bool failed = false;       // origin unreachable
        bool headSeen = false;
        std::uint64_t upBytes = 0;   // origin -> edge
        std::uint64_t downBytes = 0; // edge -> origin
        std::shared_ptr<OriginStream> origin;
        bool isWebsocket = false;  // 101 upgrade: END_STREAM means "stop proxying"
        // The request head's origin connection is opened by the pump, never by
        // the h2 callback: the callback cannot wait for a response that itself
        // depends on the callback returning (the request body is queued only
        // afterwards). See OriginStream::begin().
        std::string originError;
        std::string reqPath;   // for logging once the origin answers
        // Bytes from the edge waiting to be handed to the origin. They are
        // queued instead of written inline because the h2 write path may block
        // waiting for flow-control credit; writing to the origin from there
        // deadlocks a duplex stream (the origin cannot drain its own replies,
        // so it stops reading, so our write blocks, so we never resume).
        std::vector<std::uint8_t> toOrigin;
        std::size_t toOriginOff = 0;
        bool endFromEdge = false;    // edge signalled END_STREAM
        // Set from inside an h2 callback. The pump may itself be dispatching
        // frames (write_data waits for flow-control credit), so a callback must
        // never erase from the stream map -- that would invalidate the
        // iteration the pump is holding. Flags are applied by the pump instead.
        bool resetByEdge = false;
        bool writeFailed = false;
        bool edgeDone = false;     // websocket peer finished sending
        // Bytes produced by the origin that the edge's flow-control window has
        // not accepted yet. Holding them here (instead of blocking inside the
        // h2 write) keeps the read side of the relay running.
        std::vector<std::uint8_t> toEdge;
        std::size_t toEdgeOff = 0;
        bool originDone = false;   // origin finished; send END_STREAM once drained
        bool endSent = false;      // END_STREAM already emitted for this stream
    };
    std::map<std::uint32_t, StreamCtx> streams;
    std::vector<std::uint8_t> ctrlRx;
    std::uint32_t ctrlStream = 0;
    bool needBootstrap = false;

    // Declared up front so the callbacks below can call them.
    std::function<bool(std::uint32_t, const std::string&,
                       const std::vector<std::pair<std::string, std::string>>&, bool)>
        srvWriteHdrs;
    std::function<bool(std::uint32_t, const std::uint8_t*, std::size_t, bool)> srvWriteData;
    std::function<bool(std::uint32_t, std::uint32_t)> srvRst;
    std::function<std::size_t(std::uint32_t, const std::uint8_t*, std::size_t, bool)> srvWriteDataSome;

    // Relays the origin's response head. Defined before the h2 callbacks so the
    // pump can invoke it as soon as an OriginStream becomes Ready.
    std::function<void(std::uint32_t, const std::string&, bool)> onResponse;

    H2Server::Callbacks cb;
    cb.on_request = [&](const H2Server::Request& r) {
        auto& s = streams[r.streamId];
        s.method = r.method;
        s.path = r.path;
        s.headers = r.headers;
        auto it = r.headers.find(kUpgradeHeader);
        if (it != r.headers.end() && it->second == kUpgradeControlStream) {
            s.isControl = true;
            ctrlStream = r.streamId;
            LD("[tunnel] control stream opened (id " + std::to_string(r.streamId) + ")");
            needBootstrap = true;
            return;
        }
        // The edge pushes ingress configuration on its own stream. It never
        // reaches the origin: we just acknowledge it and keep the tunnel alive.
        if (it != r.headers.end() && it->second == kUpgradeConfiguration) {
            s.isConfig = true;
            LD("[tunnel] configuration update from edge (stream " +
               std::to_string(r.streamId) + ")");
            return;
        }

        // Proxied request: connect to the origin immediately and relay the
        // request head. The body is pumped as DATA arrives, so long-lived
        // protocols (VLESS over WebSocket) work without buffering.
        LD("[tunnel] request " + r.method + " " + r.path);
        if (h2_trace_enabled()) {
            std::fprintf(stderr, "[tunnel] --- request headers (%zu) ---\n", r.headers.size());
            for (auto& kv : r.headers)
                std::fprintf(stderr, "  '%s' = '%.100s'\n", kv.first.c_str(), kv.second.c_str());
            std::fflush(stderr);
        }
        auto stream = std::make_shared<OriginStream>();
        // The edge does not forward the standard WebSocket upgrade headers.
        // Instead it marks the stream through cf-cloudflared-proxy-connection-
        // upgrade: websocket. Restore the real headers so the origin performs a
        // proper 101 handshake; otherwise it falls back to plain HTTP routing.
        std::vector<std::pair<std::string, std::string>> hdrs;
        bool isWebsocket = false;
        std::string wsKey;
        for (auto& kv : r.headers) {
            const std::string& k = kv.first;
            if (k.empty() || k[0] == ':') continue;
            if (k == kUpgradeHeader) {
                if (kv.second == "websocket") isWebsocket = true;
                continue;
            }
            if (k == "sec-websocket-key") wsKey = kv.second;
            // The edge ships the original HTTP/1 headers base64-serialized in a
            // single header; decode them so the origin sees the real request.
            if (k == "cf-cloudflared-request-headers") {
                deserialize_user_headers(kv.second, hdrs);
                continue;
            }
            if (k == "cf-connecting-ip" || k == "cf-ray" || k == "cf-visitor" ||
                k == "cf-ipcountry" || k == "cdn-loop" || k == "cf-cloudflared-response-meta") {
                continue;
            }
            hdrs.emplace_back(k, kv.second);
        }
        // The live edge signals a WebSocket with
        // cf-cloudflared-proxy-connection-upgrade: websocket (cloudflared's
        // isWebsocketUpgrade) and does not forward sec-websocket-key. A key is
        // still accepted when present (local harnesses and older edges send it)
        // but is never invented: the origin must not hash a key the client
        // never sent.
        if (!wsKey.empty()) {
            isWebsocket = true;
            hdrs.emplace_back("Sec-WebSocket-Key", wsKey);
        }
        if (isWebsocket) {
            hdrs.emplace_back("Upgrade", "websocket");
            hdrs.emplace_back("Connection", "Upgrade");
            hdrs.emplace_back("Sec-WebSocket-Version", "13");
        }
        // Only *start* the connection. The response head is collected by the
        // pump (see pumpOrigins), because a blocking wait here deadlocks any
        // request that carries a body: the edge's DATA is queued by the pump
        // after this callback returns, so the origin would wait forever for a
        // body we have not forwarded yet.
        std::string oerr;
        s.origin = stream;
        s.isWebsocket = isWebsocket;
        s.reqPath = r.path;
        if (!stream->begin(cfg.originHost, cfg.originPort, r.method, r.path, hdrs,
                           cfg.connectTimeoutMs, oerr)) {
            log("[tunnel] origin connect failed: " + oerr);
            s.failed = true;
            s.originError = oerr;
        }
        // Nothing else happens here; on_response() is invoked by the pump once
        // the origin actually answered.
    };
    // Relays the origin's status line and headers. For a WebSocket upgrade this
    // is the 101 + Sec-WebSocket-Accept the client needs before any data flows.
    onResponse = [&](std::uint32_t id, const std::string& head, bool isWebsocket) {
        auto it = streams.find(id);
        if (it == streams.end()) return;
        auto& s = it->second;
        int statusCode = 0;
        // Mirrors connection/http2.go WriteRespHeaders() + AckConnection():
        //   * user headers are all serialized into cf-cloudflared-response-headers
        //     so HTTP/2 header validation never sees HTTP/1 values;
        //   * content-length is ALSO sent as a real h2 header because the edge
        //     uses it for framing;
        //   * the websocket handshake headers (Connection/Upgrade/
        //     Sec-Websocket-Accept) are real h2 headers too -- IsWebsocketClientHeader;
        //   * 101 becomes 200 because HTTP/2 forbids switching protocols.
        std::vector<std::pair<std::string, std::string>> userHeaders;
        bool haveLength = false;
        std::string contentLength;
        {
            std::istringstream hs(head);
            std::string statusLine;
            std::getline(hs, statusLine);
            std::istringstream sl(statusLine);
            std::string ver;
            sl >> ver >> statusCode;
            std::string line;
            while (std::getline(hs, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                if (line.empty()) continue;
                auto colon = line.find(':');
                if (colon == std::string::npos) continue;
                std::string name = line.substr(0, colon);
                std::string value = line.substr(colon + 1);
                while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
                    value.erase(value.begin());
                while (!value.empty() && (value.back() == ' ' || value.back() == '\t'))
                    value.pop_back();
                std::string ln = name;
                for (auto& c : ln) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
                if (ln == "content-length") { contentLength = value; haveLength = true; }
                if (ln == "transfer-encoding" || ln == "proxy-connection") continue;
                userHeaders.emplace_back(name, value);
            }
        }
        if (statusCode == 0) statusCode = 502;
        if (!srvWriteHdrs) return;

        // HTTP/2 removed 101: the edge derives the upgrade from the headers.
        std::string statusOut = (statusCode == 101) ? "200" : std::to_string(statusCode);

        std::vector<std::pair<std::string, std::string>> h2hdrs;
        if (haveLength) h2hdrs.emplace_back("content-length", contentLength);
        for (auto& kv : userHeaders) {
            std::string ln = kv.first;
            for (auto& c : ln) c = static_cast<char>(::tolower(static_cast<unsigned char>(c)));
            // Only the websocket client headers escape serialization.
            if (is_websocket_client_header(ln)) h2hdrs.emplace_back(ln, kv.second);
        }
        h2hdrs.emplace_back("cf-cloudflared-response-headers", serialize_user_headers(userHeaders));
        h2hdrs.emplace_back("cf-cloudflared-response-meta",
                            "{\"src\":\"origin\",\"flow_rate_limited\":false}");

        if (h2_trace_enabled()) {
            std::fprintf(stderr, "[tunnel] response %s (%zu h2 hdrs)\n",
                         statusOut.c_str(), h2hdrs.size());
            for (auto& kv : h2hdrs)
                std::fprintf(stderr, "  %s: %.120s\n", kv.first.c_str(), kv.second.c_str());
            std::fflush(stderr);
        }
        srvWriteHdrs(id, statusOut, h2hdrs, false);
        s.responded = true;
        ++status.requestsServed;
        LD("[tunnel] origin " + std::to_string(statusCode) + " -> h2 " + statusOut + " on " +
           s.reqPath);
    };
    cb.on_data = [&](std::uint32_t id, const std::uint8_t* d, std::size_t n) {
        auto it = streams.find(id);
        if (it == streams.end()) return;
        if (it->second.isControl) {
            ctrlRx.insert(ctrlRx.end(), d, d + n);
            return;
        }
        if (it->second.isConfig) {
            it->second.configBody.append(reinterpret_cast<const char*>(d), n);
            return;
        }
        // Queue only. The main loop moves these bytes to the origin, so this
        // callback never blocks on either side of the relay.
        if (it->second.origin && n) {
            it->second.toOrigin.insert(it->second.toOrigin.end(), d, d + n);
        }
    };
    cb.on_end = [&](std::uint32_t id) {
        auto it = streams.find(id);
        if (it == streams.end()) return;
        // The configuration update is HEADERS + DATA + END_STREAM and has no
        // origin at all. Record the end so the pump acknowledges it only once
        // the body is complete; acking on the HEADERS frame dropped the config
        // body entirely, so the ingress hostnames never reached the panel.
        if (it->second.isConfig) {
            it->second.endSeen = true;
            return;
        }
        if (it->second.isControl || !it->second.origin) return;
        // cloudflared never half-closes a hijacked WebSocket: it just stops
        // reading from the eyeball (stream.Pipe's reader sees EOF). Shutting
        // down the origin's write side instead would end the TCP stream under
        // a protocol that is still meant to flow downstream.
        if (it->second.isWebsocket) {
            // Deferred: for an upgrade request END_STREAM just means "the GET
            // has no body". The pump only acts on it after the 101 is relayed.
            it->second.endFromEdge = false;
            it->second.edgeDone = true;
            return;
        }
        // Defer the half-close: queued bytes must reach the origin first, and
        // the write itself may have to wait for flow-control credit.
        it->second.endFromEdge = true;
    };

    // The edge reset the stream. Never erase here: this callback can fire from
    // inside the pump's own write path, and erasing would invalidate the
    // iteration the pump is holding. Flag it and let the pump clean up.
    cb.on_reset = [&](std::uint32_t id) {
        auto it = streams.find(id);
        if (it == streams.end()) return;
        it->second.resetByEdge = true;
    };
    cb.on_error = [&](const std::string& e) { log("[tunnel] error: " + e); };

    H2Server* srv = H2Server::create(cb);
    srvWriteHdrs = [srv](std::uint32_t id, const std::string& st,
                         const std::vector<std::pair<std::string, std::string>>& h, bool end) {
        return srv->write_headers(id, st, h, end);
    };
    srvWriteData = [srv](std::uint32_t id, const std::uint8_t* d, std::size_t n, bool end) {
        return srv->write_data(id, d, n, end);
    };
    srvRst = [srv](std::uint32_t id, std::uint32_t code) { return srv->write_rst_stream(id, code); };
    srvWriteDataSome = [srv](std::uint32_t id, const std::uint8_t* d, std::size_t n, bool end) {
        return srv->write_data_some(id, d, n, end);
    };

    std::string err;
    if (!srv->connect(cfg.edgeHost, cfg.edgePort, cfg.edgeSni, cfg.connectTimeoutMs, err)) {
        status.error = err;
        delete srv;
        return false;
    }
    if (!srv->startHttp2(cfg.connectTimeoutMs, err)) {
        status.error = err;
        delete srv;
        return false;
    }
    status.connected = true;
    LI("[tunnel] connected to edge");
    publish();

    // Relays whatever the origin has produced back to the edge. Runs every
    // loop iteration so a long-lived stream stays responsive in both directions.
    auto pumpOrigins = [&]() {
        std::vector<std::uint32_t> dead;
        // Iterate a snapshot: writing to the edge can re-enter our h2 callbacks,
        // which insert into `streams`. A reference into that map would dangle.
        std::vector<std::uint32_t> ids;
        ids.reserve(streams.size());
        for (auto& kv : streams) ids.push_back(kv.first);
        for (auto id : ids) {
            auto found = streams.find(id);
            if (found == streams.end()) continue;
            auto& s = found->second;
            if (s.isConfig) {
                // Wait for the whole body. The edge sends the update as
                // HEADERS, then DATA carrying
                // {"version":N,"config":{"ingress":[...]}} , then END_STREAM.
                // Answering before the DATA arrives (the old behaviour) threw
                // the ingress list away, so a named tunnel could never learn
                // its own public hostname.
                if (!s.endSeen) continue;
                if (!s.responded) {
                    s.responded = true;
                    const auto hosts = ingress_hostnames(s.configBody);
                    const int version = ingress_version(s.configBody);
                    if (!hosts.empty()) {
                        // Publish the hostnames so the panel can show them and
                        // the subscription generators can use them.
                        status.hostnames = hosts;
                        std::string joined;
                        for (std::size_t i = 0; i < hosts.size(); ++i) {
                            if (i) joined += ", ";
                            joined += hosts[i];
                        }
                        LI("[tunnel] ingress hostnames: " + joined);
                        publish();
                    }
                    // Mirror cloudflared: it writes the marshalled
                    // pogs.UpdateConfigurationResponse as the response body.
                    const std::string ack = config_update_ack(version);
                    srvWriteHdrs(id, "200",
                                  {{"content-type", "application/json"},
                                   {"content-length", std::to_string(ack.size())}},
                                  false);
                    srvWriteData(id, reinterpret_cast<const std::uint8_t*>(ack.data()),
                                 ack.size(), true);
                    if (h2_trace_enabled())
                        std::fprintf(stderr, "[tunnel] config body (%zu bytes): %.400s\n",
                                     s.configBody.size(), s.configBody.c_str());
                }
                dead.push_back(id);
                continue;
            }
            if (s.resetByEdge) {
                LD("[tunnel] edge reset stream " + std::to_string(id) + " (down=" +
                    std::to_string(s.downBytes) + " up=" + std::to_string(s.upBytes) + ")");
                if (s.origin) s.origin->close();
                dead.push_back(id);
                continue;
            }
            if (s.isControl || !s.origin) continue;
            if (s.failed) {
                const std::string msg = "origin unreachable";
                srvWriteHdrs(id, "502", {{"content-type", "text/plain"}}, false);
                srvWriteData(id, reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size(), true);
                dead.push_back(id);
                continue;
            }
            // Drive the origin connection (connect -> request head -> response
            // head). This is the only place that spins that state machine, so
            // no h2 callback ever has to wait for the origin. A Pending origin
            // is NOT skipped: a request with a body only completes once that
            // body has been forwarded to the origin.
            bool headReady = s.responded;
            if (!headReady) {
                const OriginStream::Step st = s.origin->step();
                if (st == OriginStream::Step::Failed) {
                    log("[tunnel] origin failed on " + s.reqPath + ": " + s.origin->errorText());
                    s.failed = true;
                    s.originError = s.origin->errorText();
                    const std::string msg = "origin unreachable";
                    srvWriteHdrs(id, "502", {{"content-type", "text/plain"}}, false);
                    srvWriteData(id, reinterpret_cast<const std::uint8_t*>(msg.data()), msg.size(),
                                 true);
                    dead.push_back(id);
                    continue;
                }
                if (st == OriginStream::Step::Ready) {
                    onResponse(id, s.origin->responseHead(), s.isWebsocket);
                    headReady = s.responded;
                }
            }

            // Move whatever the edge delivered into the origin's output queue.
            // This never blocks: unaccepted bytes stay buffered and are pushed
            // by flush() below on subsequent iterations.
            if (!s.toOrigin.empty()) {
                const std::size_t left = s.toOrigin.size() - s.toOriginOff;
                if (left) {
                    if (!s.origin->write(s.toOrigin.data() + s.toOriginOff, left)) {
                        log("[tunnel] origin write failed on stream " + std::to_string(id));
                        if (srvRst) srvRst(id, 0x2);  // INTERNAL_ERROR
                        s.origin->close();
                        dead.push_back(id);
                        continue;
                    }
                    s.downBytes += left;
                    s.toOriginOff += left;
                }
                // Drop ONLY the bytes that were just written. `write` above can
                // re-enter our h2 callbacks (it may wait for flow-control
                // credit), and those callbacks append to this very vector --
                // clearing it wholesale would silently discard the bytes that
                // arrived while we were blocked.
                if (s.toOriginOff >= s.toOrigin.size()) {
                    s.toOrigin.clear();
                    s.toOriginOff = 0;
                } else {
                    s.toOrigin.erase(s.toOrigin.begin(),
                                     s.toOrigin.begin() + static_cast<std::ptrdiff_t>(s.toOriginOff));
                    s.toOriginOff = 0;
                }
            }
            // Push anything the socket refused earlier. Without this the tail
            // of a burst would sit in our buffer forever.
            if (s.origin->hasPendingOutput() && !s.origin->flush()) {
                log("[tunnel] origin flush failed on stream " + std::to_string(id));
                s.origin->close();
                dead.push_back(id);
                continue;
            }
            if (s.edgeDone && s.isWebsocket && s.responded) {
                // The eyeball hung up. Tell the origin properly, then let the
                // remaining downstream bytes drain before the stream is retired.
                //
                // Only valid once the 101 has been relayed: a WebSocket upgrade
                // request is a GET with END_STREAM on its HEADERS frame (there is
                // no body), and acting on that before the handshake completes
                // closes every new WebSocket the moment it is opened.
                send_ws_close(s.origin);
                s.edgeDone = false;
                s.originDone = true;
            }
            if (s.endFromEdge && s.origin->requestSent() && !s.origin->hasPendingOutput()) {
                // Everything the edge sent has reached the origin; now it may
                // see end-of-request while we keep reading its reply. Wait for
                // the queue to drain first, otherwise a half-close would
                // truncate the request. requestSent() matters because the
                // request head itself is written by step(), asynchronously: for
                // a plain GET the END_STREAM arrives together with the HEADERS,
                // so half-closing here without that check cut the head in half
                // and the origin answered with a reset instead of a response.
                ::shutdown(s.origin->fd(), SHUT_WR);
                s.endFromEdge = false;
            }

            // Push queued origin output towards the edge, accepting only as
            // many bytes as the flow-control window allows right now. Blocking
            // here (the old behaviour) froze the origin read below, which in
            // turn stopped the origin from socket-draining its own writes.
            if (!s.endSent && s.toEdgeOff < s.toEdge.size() && srvWriteDataSome) {
                const std::size_t left = s.toEdge.size() - s.toEdgeOff;
                const bool isLast = s.originDone && (left <= 16384);
                std::size_t took = srvWriteDataSome(id, s.toEdge.data() + s.toEdgeOff, left,
                                                    isLast);
                if (took == static_cast<std::size_t>(-1)) {
                    log("[tunnel] h2 write failed on stream " + std::to_string(id));
                    s.origin->close();
                    dead.push_back(id);
                    continue;
                }
                s.toEdgeOff += took;
                s.upBytes += static_cast<std::uint64_t>(took);
                // write_data_some already attached END_STREAM when it accepted
                // the final bytes of a finished origin. Remember that, or the
                // tail block below sends a SECOND empty END_STREAM on the same
                // stream, which the edge rejects with PROTOCOL_ERROR (code=1)
                // and closes the whole connection -- seen as a download dying
                // at a random offset with no local error.
                if (isLast && took == left) s.endSent = true;
                if (s.toEdgeOff >= s.toEdge.size()) {
                    s.toEdge.clear();
                    s.toEdgeOff = 0;
                } else if (s.toEdgeOff > 256 * 1024) {
                    s.toEdge.erase(s.toEdge.begin(),
                                   s.toEdge.begin() + static_cast<std::ptrdiff_t>(s.toEdgeOff));
                    s.toEdgeOff = 0;
                }
            }
            // Only read more from the origin while the queue is small, so a slow
            // edge applies backpressure instead of growing memory without bound.
            constexpr std::size_t kEdgeQueueHighWater = 512 * 1024;
            // Before the response head arrives, OriginStream::step() owns the
            // read side; body bytes must not be drained here or they would be
            // relayed to the edge before the HEADERS frame that precedes them.
            const bool canRead =
                headReady && (s.toEdge.size() - s.toEdgeOff) < kEdgeQueueHighWater;

            std::uint8_t buf[16384];
            bool gotData = false;
            for (; canRead;) {
                int n = s.origin->readSome(buf, sizeof(buf), 0);
                if (n > 0) {
                    // Headers were already sent when the origin answered, so we
                    // only stream DATA from here on.
                    s.toEdge.insert(s.toEdge.end(), buf, buf + n);
                    gotData = true;
                    continue;   // keep draining; the edge window caps the write
                }
                if (n == 0) break;               // nothing more right now
                // n < 0: origin closed. Flush whatever is still queued, then
                // send END_STREAM -- dropping the queue here would truncate the
                // response exactly as the flow-control window reopened.
                s.originDone = true;
                s.origin->close();
                break;
            }
            // Push immediately: waiting for the next pump iteration costs one
            // full poll interval, which turned a small reply into a multi-second
            // stall and made long transfers crawl.
            // Never precede the response HEADERS: HTTP/2 forbids DATA before
            // headers, and the earlier ordering bug shipped data frames first.
            if (gotData && s.responded && !s.endSent && srvWriteDataSome) {
                const std::size_t left = s.toEdge.size() - s.toEdgeOff;
                const bool isLast = s.originDone && (left <= 16384);
                std::size_t took = srvWriteDataSome(id, s.toEdge.data() + s.toEdgeOff, left,
                                                    isLast);
                if (took == static_cast<std::size_t>(-1)) {
                    log("[tunnel] h2 write failed on stream " + std::to_string(id));
                    s.origin->close();
                    dead.push_back(id);
                    continue;
                }
                s.toEdgeOff += took;
                s.upBytes += static_cast<std::uint64_t>(took);
                // Same duplicate-END_STREAM guard as above. These two blocks run
                // back to back in one iteration, so without it a normal reply
                // ending inside gotData emitted END_STREAM twice.
                if (isLast && took == left) s.endSent = true;
                if (s.toEdgeOff >= s.toEdge.size()) {
                    s.toEdge.clear();
                    s.toEdgeOff = 0;
                }
            }
            // Origin finished and everything reached the edge: retire the stream,
            // emitting END_STREAM only if one was not already sent with the last
            // data frame.
            if (s.originDone && s.toEdgeOff >= s.toEdge.size()) {
                if (!s.endSent) {
                    s.endSent = true;
                    if (srvWriteDataSome) srvWriteDataSome(id, nullptr, 0, true);
                }
                dead.push_back(id);
            }
        }
        for (auto id : dead) streams.erase(id);
    };

    int tick = 0;
    while (!stopping_) {
        // Poll with a timeout only when there is nothing left to push. If any
        // stream still has queued bytes, loop immediately so a long-lived
        // WebSocket is not throttled to one chunk per idlePollMs (which made a
        // 2-byte VLESS reply take seconds to surface).
        // "Backlog" means bytes are actually *unsent* (offset comparisons, not
        // emptiness): a long-lived WebSocket keeps a non-empty buffer whose
        // offset has caught up, and testing emptiness there made the loop
        // poll(0) forever at 100% CPU.
        // Two different kinds of "work waiting":
        //   * bytes already queued for one of the two peers -> push them now
        //   * an origin still connecting/awaiting its response head -> advance
        //     its non-blocking state machine soon
        // The first must poll at 0, but the second must NOT: spinning at
        // poll(0) saturates this thread's CPU, and the origin is the *same
        // process's* HTTP server, so it starves and the download never
        // completes (observed as a 15s edge timeout). A 1ms tick keeps the
        // state machine moving without monopolising the core.
        bool backlog = false;
        bool hasPendingOrigin = false;
        // True while any proxied stream is open. srv->poll() only waits on the
        // EDGE socket, so nothing wakes us when the origin receives bytes: they
        // sit in the origin socket until the next pumpOrigins(). Waiting the
        // full idlePollMs there cost one 16 KB read per 100 ms (~160 KB/s), a
        // 2-4 s pause per flow-control cycle, and ~100 ms on every protocol
        // round trip -- a TLS handshake through the tunnel measured 1-2 s
        // instead of the ~50 ms the 14 ms edge RTT allows. With a session open
        // the wait is shortened to activePollMs instead.
        bool activeStream = false;
        for (auto& kv : streams) {
            auto& s = kv.second;
            if (!s.origin || s.isControl) continue;
            activeStream = true;
            // Bytes queued for the edge only count as backlog while the edge
            // still grants credit. Without this check a closed flow-control
            // window looked like "work waiting", so the loop called poll(0)
            // forever: 100% CPU, a trace line per iteration, and the peer's
            // WINDOW_UPDATE was the only thing that could ever clear it. That
            // is the "repeated short stall" seen on long downloads.
            const bool waitingForCredit =
                s.toEdgeOff < s.toEdge.size() && !srv->send_credit_available(kv.first);
            if (waitingForCredit) continue;
            if (s.toEdgeOff < s.toEdge.size() || s.toOriginOff < s.toOrigin.size() ||
                s.origin->hasPendingOutput()) {
                backlog = true;
                break;
            }
            if (!s.responded && s.origin->pending()) hasPendingOrigin = true;
        }
        int pollTimeoutMs;
        if (backlog) pollTimeoutMs = 0;
        else if (hasPendingOrigin) pollTimeoutMs = 1;
        else if (activeStream) pollTimeoutMs = cfg.activePollMs;
        else pollTimeoutMs = cfg.idlePollMs;
        if (!srv->poll(pollTimeoutMs)) {
            // The edge went away (or sent GOAWAY). Leave the loop so the
            // supervisor can reconnect with backoff; staying here meant every
            // request hit a dead connection and the loop span at full speed.
            status.error = "edge connection lost";
            log("[tunnel] " + status.error);
            status.connected = false;
            break;
        }
        pumpOrigins();

        // Periodic accounting. Per-stream lines are only emitted with
        // BPB_TUNNEL_TRACE (they cost 4 journal lines per second per stream and
        // drowned the log on a 40-minute run); otherwise a single aggregate
        // line every ~60s at the idle poll rate keeps the journal readable.
        ++tick;
        if (h2_trace_enabled() && tick % 30 == 0) {
            for (auto& kv : streams) {
                if (kv.second.isControl) continue;
                LD("[tunnel] stream " + std::to_string(kv.first) + " down=" +
                    std::to_string(kv.second.downBytes) + " up=" +
                    std::to_string(kv.second.upBytes) + " queued=" +
                    std::to_string(kv.second.origin ? kv.second.origin->pendingOutputBytes() : 0) +
                    " toOrigin=" + std::to_string(kv.second.toOrigin.size() - kv.second.toOriginOff));
            }
        } else if (!h2_trace_enabled() && tick % 600 == 0 && !streams.empty()) {
            std::uint64_t down = 0, up = 0;
            for (auto& kv : streams) {
                down += kv.second.downBytes;
                up += kv.second.upBytes;
            }
            LD("[tunnel] " + std::to_string(streams.size()) + " stream(s), down=" +
                std::to_string(down) + " up=" + std::to_string(up) +
                ", served=" + std::to_string(status.requestsServed));
        }

        if (needBootstrap) {
            needBootstrap = false;
            srv->write_headers(ctrlStream, "200",
                               {{"content-type", "application/octet-stream"}}, false);
            auto boot = RpcStream::encode_bootstrap(1);
            srv->write_data(ctrlStream, boot.data(), boot.size(), false);
            LD("[tunnel] sent bootstrap");

            // Wait for the bootstrap Return.
            std::size_t consumed = 0;
            bool got = false;
            for (int i = 0; i < cfg.registerTimeoutMs / cfg.idlePollMs && !stopping_; ++i) {
                if (!srv->poll(cfg.idlePollMs)) {
                    status.error = "edge connection lost during bootstrap";
                    log("[tunnel] " + status.error);
                    delete srv;
                    return false;
                }
                // Proxied streams keep flowing while the control stream is
                // still handshaking; otherwise every registration stalls
                // traffic for up to registerTimeoutMs.
                if (!streams.empty()) pumpOrigins();
                for (auto& m : split_messages(ctrlRx, consumed)) {
                    if (m.first < consumed) continue;
                    consumed = m.first + m.second;
                    std::uint16_t kind = 0;
                    std::uint32_t id = 0;
                    if (RpcStream::peek(ctrlRx.data() + m.first, m.second, kind, id) &&
                        kind == kRpcReturn) {
                        got = true;
                    }
                }
                if (got) break;
            }
            if (!got) {
                status.error = "bootstrap timed out";
                log("[tunnel] " + status.error);
                delete srv;
                return false;
            }

            // registerConnection
            const auto uuidBytes = uuid_to_bytes(cfg.tunnelId);
            auto call = RpcStream::encode_call(
                2, 1, kRegistrationServerId, kMethodRegisterConnection,
                [&](capnp::Message& m) {
                    auto params = m.alloc_struct(2, 3);
                    params.set_u8(0, 0);
                    auto auth = m.alloc_struct(0, 2);
                    auth.set_text(0, cfg.accountTag);
                    auth.set_data(1, cfg.tunnelSecret.data(), cfg.tunnelSecret.size());
                    params.set_struct(0, auth);
                    params.set_data(1, uuidBytes.data(), uuidBytes.size());
                    auto client = m.alloc_struct(0, 4);
                    client.set_data(0, uuidBytes.data(), uuidBytes.size());
                    client.set_text(2, "2026.10.6");
                    client.set_text(3, "linux_amd64");
                    auto opts = m.alloc_struct(1, 2);
                    opts.set_struct(0, client);
                    opts.set_data(1, "127.0.0.1", 9);
                    params.set_struct(2, opts);
                    return params;
                });
            srv->write_data(ctrlStream, call.data(), call.size(), false);
            LD("[tunnel] sent registerConnection");

            std::size_t before = consumed;
            bool registered = false;
            for (int i = 0; i < cfg.registerTimeoutMs / cfg.idlePollMs && !stopping_; ++i) {
                if (!srv->poll(cfg.idlePollMs)) {
                    status.error = "edge connection lost during registration";
                    log("[tunnel] " + status.error);
                    delete srv;
                    return false;
                }
                if (!streams.empty()) pumpOrigins();
                for (auto& m : split_messages(ctrlRx, before)) {
                    if (m.first < before) continue;
                    before = m.first + m.second;
                    std::uint16_t kind = 0;
                    std::uint32_t id = 0;
                    if (RpcStream::peek(ctrlRx.data() + m.first, m.second, kind, id) &&
                        kind == kRpcReturn && id == 2) {
                        std::size_t off = 0;
                        std::uint16_t dw = 0, pc = 0;
                        std::string e2;
                        if (rpc_return_payload(ctrlRx.data() + m.first, m.second, off, dw, pc, e2)) {
                            registered = true;
                        } else {
                            status.error = e2;
                        }
                    }
                }
                if (registered) break;
            }
            status.registered = registered;
            publish();
            if (registered) {
                LI("[tunnel] REGISTERED with edge");
            } else {
                log("[tunnel] registration failed: " + status.error);
                delete srv;
                return false;
            }
            consumed = before;
        }
    }

    delete srv;
    return true;
}

} // namespace bpb::tunnel
