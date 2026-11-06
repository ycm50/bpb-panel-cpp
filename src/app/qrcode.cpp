#include "app/qrcode.h"

#include "net/http_client.h"
#include "util/util.h"

#include "qrcodegen.hpp"

#include <cstdint>
#include <cstring>
#include <vector>
#include <zlib.h>

namespace bpb {

namespace {

void put_u32(std::string& out, std::uint32_t value) {
    out.push_back(static_cast<char>((value >> 24) & 0xFF));
    out.push_back(static_cast<char>((value >> 16) & 0xFF));
    out.push_back(static_cast<char>((value >> 8) & 0xFF));
    out.push_back(static_cast<char>(value & 0xFF));
}

void put_chunk(std::string& out, const char* type, const std::string& data) {
    put_u32(out, static_cast<std::uint32_t>(data.size()));
    std::string crc_input(type);
    crc_input += data;
    out += type;
    out += data;
    std::uint32_t crc = static_cast<std::uint32_t>(
        crc32(0L, reinterpret_cast<const Bytef*>(crc_input.data()),
              static_cast<uInt>(crc_input.size())));
    put_u32(out, crc);
}

std::string deflate_zlib(const std::string& raw, std::string& error) {
    uLongf bound = compressBound(static_cast<uLong>(raw.size()));
    std::vector<Bytef> buffer(bound);
    int rc = compress2(buffer.data(), &bound,
                       reinterpret_cast<const Bytef*>(raw.data()),
                       static_cast<uLong>(raw.size()), 9);
    if (rc != Z_OK) {
        error = "zlib compress failed (" + std::to_string(rc) + ")";
        return {};
    }
    return std::string(reinterpret_cast<const char*>(buffer.data()), static_cast<std::size_t>(bound));
}

// Compares two host names case-insensitively and ignoring a trailing dot. DNS
// names are case-insensitive, and the subscription generator deliberately
// randomises the case of the SNI it publishes -- so a panel URL pasted from a
// subscription can legitimately differ in case from the Host header.
bool host_equal(std::string_view a, std::string_view b) {
    auto norm = [](std::string_view s) {
        std::string out(s);
        while (!out.empty() && out.back() == '.') out.pop_back();
        return to_lower(out);
    };
    return norm(a) == norm(b);
}

// The host part of a Host-like header, without the port and without IPv6
// brackets. "example.com:443" -> "example.com", "[::1]:8080" -> "::1".
std::string host_only(std::string_view value) {
    std::string s(value);
    const auto colon = s.rfind(':');
    if (colon != std::string::npos) {
        const std::string tail = s.substr(colon + 1);
        // Only split when the tail is a port: a bare IPv6 literal has several
        // colons and its last group is not numeric across the whole tail.
        if (!tail.empty() && tail.size() <= 5 &&
            tail.find_first_not_of("0123456789") == std::string::npos) {
            s = s.substr(0, colon);
        }
    }
    if (s.size() >= 2 && s.front() == '[' && s.back() == ']') s = s.substr(1, s.size() - 2);
    return trim(s);
}

} // namespace

bool generate_qr_png(const std::string& data, std::string& png, std::string& error) {
    using qrcodegen::QrCode;
    QrCode qr = QrCode::encodeText(data.c_str(), QrCode::Ecc::MEDIUM);

    int modules = qr.getSize();
    int scale = 8;
    int margin = 4;
    int size = (modules + margin * 2) * scale;

    std::string raw;
    raw.reserve(static_cast<std::size_t>(size) * (static_cast<std::size_t>(size) * 4 + 1));
    for (int y = 0; y < size; ++y) {
        raw.push_back('\0');  // filter type 0 per scanline
        int my = y / scale - margin;
        for (int x = 0; x < size; ++x) {
            int mx = x / scale - margin;
            bool dark = (my >= 0 && my < modules && mx >= 0 && mx < modules) &&
                        qr.getModule(mx, my);
            if (dark) {
                raw += static_cast<char>(15);
                raw += static_cast<char>(23);
                raw += static_cast<char>(42);
                raw += static_cast<char>(255);
            } else {
                raw += static_cast<char>(255);
                raw += static_cast<char>(255);
                raw += static_cast<char>(255);
                raw += static_cast<char>(255);
            }
        }
    }

    std::string idat = deflate_zlib(raw, error);
    if (idat.empty()) return false;

    std::string ihdr;
    ihdr.reserve(13);
    put_u32(ihdr, static_cast<std::uint32_t>(size));
    put_u32(ihdr, static_cast<std::uint32_t>(size));
    ihdr.push_back(8);   // bit depth
    ihdr.push_back(6);   // color type RGBA
    ihdr.push_back(0);   // compression
    ihdr.push_back(0);   // filter
    ihdr.push_back(0);   // interlace

    png.clear();
    png.reserve(idat.size() + 128);
    png += std::string("\x89PNG\r\n\x1a\n", 8);
    put_chunk(png, "IHDR", ihdr);
    put_chunk(png, "IDAT", idat);
    put_chunk(png, "IEND", "");
    return true;
}

namespace app {

http::Response qrcode_route(
    const http::Request& req,
    const std::function<http::Response(int, const std::string&)>& render_error) {
    auto params = req.params();
    const std::string data = params.count("data") ? params["data"] : std::string();
    if (data.empty()) return http::Response::text(400, "缺少 data 参数");

    // Only render QR codes that point back at this panel (same rule as the TS
    // implementation): the endpoint is unauthenticated, so without this it would
    // happily generate an image for any URL an attacker wanted a victim to scan.
    //
    // The check used to compare parsed.host against the Host header verbatim,
    // which broke in tunnel mode in two separate ways:
    //   * the Host header arriving from the tunnel was the ORIGIN address
    //     (127.0.0.1:8080), because the edge carries the real name in the
    //     HTTP/2 :authority pseudo-header, so every public URL looked foreign;
    //   * a port in the header made "name:443" unequal to "name".
    // Both are handled here: the panel's own public name is derived from the
    // request, and the comparison ignores port, case and a trailing dot.
    //
    // X-Forwarded-Host is consulted first. When the connector is later taught to
    // pass :authority through, it lands there; today the Host is already correct
    // because the tunnel restores it, so this is defence in depth rather than the
    // mechanism.
    std::string public_host = req.header("x-forwarded-host");
    if (public_host.empty()) public_host = req.header("host");

    net::httpc::Url parsed;
    std::string error;
    if (net::httpc::parse_url(data, parsed, error)) {
        const std::string qr_host = host_only(parsed.host);
        const std::string self_host = host_only(public_host);
        if (!self_host.empty() && !qr_host.empty() && !host_equal(qr_host, self_host)) {
            // Accept a subdomain of the public name as well: the panel may be
            // reached through a wildcard ingress entry, and the hostname shown in
            // the subscription can be a sibling under the same zone.
            const bool suffix = ends_with(to_lower(qr_host), "." + to_lower(self_host));
            if (!suffix) return render_error(404, "页面不存在");
        }
    }

    std::string png;
    if (!generate_qr_png(data, png, error)) {
        return http::Response::text(500, "二维码生成失败： " + error);
    }
    http::Response res;
    res.status = 200;
    res.set("Content-Type", "image/png");
    res.set("Cache-Control", "no-store");
    res.body = std::move(png);
    return res;
}

} // namespace app
} // namespace bpb
