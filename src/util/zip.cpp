#include "util/zip.h"

#include <cstdint>
#include <cstring>
#include <zlib.h>

namespace bpb {

namespace {

void u16(std::string& out, std::uint16_t v) {
    out.push_back(static_cast<char>(v & 0xFF));
    out.push_back(static_cast<char>((v >> 8) & 0xFF));
}

void u32(std::string& out, std::uint32_t v) {
    out.push_back(static_cast<char>(v & 0xFF));
    out.push_back(static_cast<char>((v >> 8) & 0xFF));
    out.push_back(static_cast<char>((v >> 16) & 0xFF));
    out.push_back(static_cast<char>((v >> 24) & 0xFF));
}

std::uint32_t crc_of(const std::string& data) {
    return static_cast<std::uint32_t>(crc32(0L, reinterpret_cast<const Bytef*>(data.data()),
                                            static_cast<uInt>(data.size())));
}

} // namespace

std::string zip_store(const std::vector<std::pair<std::string, std::string>>& files) {
    std::string out;
    std::string central;

    for (auto& [name, content] : files) {
        std::uint32_t crc = crc_of(content);
        std::uint32_t size = static_cast<std::uint32_t>(content.size());
        std::uint32_t offset = static_cast<std::uint32_t>(out.size());

        u32(out, 0x04034b50);
        u16(out, 20);       // version needed
        u16(out, 0);        // flags
        u16(out, 0);        // method: stored
        u16(out, 0);        // mod time
        u16(out, 0);        // mod date
        u32(out, crc);
        u32(out, size);     // compressed size
        u32(out, size);     // uncompressed size
        u16(out, static_cast<std::uint16_t>(name.size()));
        u16(out, 0);        // extra length
        out += name;
        out += content;

        u32(central, 0x02014b50);
        u16(central, 20);   // version made by
        u16(central, 20);   // version needed
        u16(central, 0);    // flags
        u16(central, 0);    // method
        u16(central, 0);    // time
        u16(central, 0);    // date
        u32(central, crc);
        u32(central, size);
        u32(central, size);
        u16(central, static_cast<std::uint16_t>(name.size()));
        u16(central, 0);    // extra
        u16(central, 0);    // comment
        u16(central, 0);    // disk number
        u16(central, 0);    // internal attrs
        u32(central, 0);    // external attrs
        u32(central, offset);
        central += name;
    }

    std::uint32_t central_size = static_cast<std::uint32_t>(central.size());
    std::uint32_t central_offset = static_cast<std::uint32_t>(out.size());
    out += central;

    u32(out, 0x06054b50);
    u16(out, 0);            // disk
    u16(out, 0);            // cd start disk
    u16(out, static_cast<std::uint16_t>(files.size()));
    u16(out, static_cast<std::uint16_t>(files.size()));
    u32(out, central_size);
    u32(out, central_offset);
    u16(out, 0);            // comment length
    return out;
}

} // namespace bpb
