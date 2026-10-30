#include "app/qrcode.h"

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

} // namespace bpb
