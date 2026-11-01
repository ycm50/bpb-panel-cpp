#include "tunnel/capnp.h"

#include <cstring>

namespace bpb::capnp {

namespace {

void put_le16(std::uint8_t* p, std::uint16_t v) {
    p[0] = static_cast<std::uint8_t>(v & 0xFF);
    p[1] = static_cast<std::uint8_t>((v >> 8) & 0xFF);
}
void put_le32(std::uint8_t* p, std::uint32_t v) {
    for (int i = 0; i < 4; ++i) p[i] = static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF);
}
void put_le64(std::uint8_t* p, std::uint64_t v) {
    for (int i = 0; i < 8; ++i) p[i] = static_cast<std::uint8_t>((v >> (i * 8)) & 0xFF);
}
std::uint16_t rd_le16(const std::uint8_t* p) {
    return static_cast<std::uint16_t>(p[0]) | (static_cast<std::uint16_t>(p[1]) << 8);
}
std::uint32_t rd_le32(const std::uint8_t* p) {
    return static_cast<std::uint32_t>(p[0]) | (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) | (static_cast<std::uint32_t>(p[3]) << 24);
}
std::uint64_t rd_le64(const std::uint8_t* p) {
    std::uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}
std::size_t align_up(std::size_t v, std::size_t a) { return (v + a - 1) / a * a; }

// Pointer encoding helpers ------------------------------------------------

// Struct pointer: kind 0, signed offset (words, from end of pointer), dataWords, ptrCount.
std::uint64_t make_struct_ptr(std::int64_t offsetWords, std::uint16_t dataWords,
                              std::uint16_t ptrCount) {
    std::uint64_t p = 0;
    p |= 0ULL;
    p |= (static_cast<std::uint64_t>(static_cast<std::uint32_t>(offsetWords) & 0x3FFFFFFF) << 2);
    p |= (static_cast<std::uint64_t>(dataWords) << 32);
    p |= (static_cast<std::uint64_t>(ptrCount) << 48);
    return p;
}

// List pointer (byte list): kind 1, signed offset, element count in the high word.
// List pointer layout: [2-bit kind=1][30-bit signed offset][3-bit elementSize][29-bit count]
// For byte/text lists elementSize = 2 (BYTE), so count starts at bit 35.
std::uint64_t make_byte_list_ptr(std::int64_t offsetWords, std::uint32_t count) {
    std::uint64_t p = 0;
    p |= 1ULL;                                   // kind = list
    p |= (static_cast<std::uint64_t>(static_cast<std::uint32_t>(offsetWords) & 0x3FFFFFFFu) << 2);
    p |= (static_cast<std::uint64_t>(2) << 32);  // elementSize = BYTE (2)
    p |= (static_cast<std::uint64_t>(count & 0x1FFFFFFFu) << 35);
    return p;
}

} // namespace

// --- Message ---------------------------------------------------------------

Message::Message(std::size_t reserve) { arena_.reserve(reserve); }

std::size_t Message::allocate(std::size_t bytes, std::size_t align) {
    std::size_t off = align_up(arena_.size(), align);
    arena_.resize(off + bytes, 0);
    return off;
}

StructBuilder Message::alloc_struct(std::uint16_t dataWords, std::uint16_t ptrCount) {
    std::size_t off = allocate(static_cast<std::size_t>(dataWords) * 8 +
                                   static_cast<std::size_t>(ptrCount) * 8,
                               8);
    return StructBuilder(this, off, dataWords, ptrCount);
}

void Message::write_u16(std::size_t off, std::uint16_t v) {
    if (off + 2 <= arena_.size()) put_le16(arena_.data() + off, v);
}
void Message::write_u32(std::size_t off, std::uint32_t v) {
    if (off + 4 <= arena_.size()) put_le32(arena_.data() + off, v);
}
void Message::write_u64(std::size_t off, std::uint64_t v) {
    if (off + 8 <= arena_.size()) put_le64(arena_.data() + off, v);
}
void Message::write_bool(std::size_t off, bool v) {
    if (off < arena_.size()) {
        if (v) arena_[off] |= 0x01;
        else arena_[off] &= 0xFE;
    }
}
void Message::write_ptr_raw(std::size_t off, std::uint64_t v) {
    if (off + 8 <= arena_.size()) put_le64(arena_.data() + off, v);
}

std::vector<std::uint8_t> Message::finish() const {
    // The segment must start with the root pointer, so reserve 8 bytes at the
    // front and shift the arena body after it.
    std::size_t bodyWords = (arena_.size() + 7) / 8;
    std::vector<std::uint8_t> seg((bodyWords + 1) * 8, 0);  // +1 word for the root pointer
    if (!arena_.empty()) {
        std::memcpy(seg.data() + 8, arena_.data(), arena_.size());
    }

    if (hasRoot_) {
        // Root pointer sits at offset 0; its target is at root_.data_offset() + 8.
        std::int64_t target = static_cast<std::int64_t>(root_.data_offset()) + 8;
        std::int64_t offsetWords = (target - 8) / 8;
        std::uint64_t p = make_struct_ptr(offsetWords, root_.data_words(), root_.ptr_count());
        put_le64(seg.data(), p);
    }

    // Framing: [segmentCount-1][segment0 words] then the segment.
    std::size_t totalWords = seg.size() / 8;
    std::vector<std::uint8_t> out(8 + seg.size(), 0);
    put_le32(out.data(), 0);
    put_le32(out.data() + 4, static_cast<std::uint32_t>(totalWords));
    std::memcpy(out.data() + 8, seg.data(), seg.size());
    return out;
}

// --- StructBuilder ---------------------------------------------------------

std::size_t StructBuilder::ptr_slot(std::uint16_t index) const {
    return dataOff_ + static_cast<std::size_t>(dataWords_) * 8 +
           static_cast<std::size_t>(index) * 8;
}

void StructBuilder::set_u8(std::uint16_t field, std::uint8_t v) {
    if (dataOff_ + field < m_->arena().size())
        m_->arena()[dataOff_ + field] = v;
}
void StructBuilder::set_u16(std::uint16_t field, std::uint16_t v) {
    m_->write_u16(dataOff_ + static_cast<std::size_t>(field) * 2, v);
}
void StructBuilder::set_u32(std::uint16_t field, std::uint32_t v) {
    m_->write_u32(dataOff_ + static_cast<std::size_t>(field) * 4, v);
}
void StructBuilder::set_u64(std::uint16_t field, std::uint64_t v) {
    m_->write_u64(dataOff_ + static_cast<std::size_t>(field) * 8, v);
}
void StructBuilder::set_bool(std::uint16_t bit, bool v) {
    m_->write_bool(dataOff_ + bit / 8, v);
}

void StructBuilder::set_union_tag(std::uint16_t bitOffset, std::uint16_t value) {
    // Read-modify-write the 16 bits starting at bitOffset (little-endian layout).
    std::size_t byte = dataOff_ + bitOffset / 8;
    int shift = bitOffset % 8;
    std::uint32_t cur = 0;
    for (int i = 0; i < 3; ++i)
        cur |= static_cast<std::uint32_t>(m_->arena()[byte + i]) << (8 * i);
    const std::uint32_t mask = static_cast<std::uint32_t>(0xFFFF) << shift;
    cur = (cur & ~mask) | ((static_cast<std::uint32_t>(value) << shift) & mask);
    for (int i = 0; i < 3; ++i)
        m_->arena()[byte + i] = static_cast<std::uint8_t>((cur >> (8 * i)) & 0xFF);
}

void StructBuilder::set_text(std::uint16_t index, const std::string& s) {
    std::size_t payload = m_->allocate(s.size() + 1, 8);
    std::memcpy(m_->arena().data() + payload, s.data(), s.size());
    m_->arena()[payload + s.size()] = 0;

    std::size_t slot = ptr_slot(index);
    std::int64_t offsetWords = (static_cast<std::int64_t>(payload) - static_cast<std::int64_t>(slot) - 8) / 8;
    m_->write_ptr_raw(slot, make_byte_list_ptr(offsetWords, static_cast<std::uint32_t>(s.size() + 1)));
}

void StructBuilder::set_data(std::uint16_t index, const void* d, std::size_t n) {
    std::size_t payload = m_->allocate(n, 8);
    if (n) std::memcpy(m_->arena().data() + payload, d, n);

    std::size_t slot = ptr_slot(index);
    std::int64_t offsetWords = (static_cast<std::int64_t>(payload) - static_cast<std::int64_t>(slot) - 8) / 8;
    m_->write_ptr_raw(slot, make_byte_list_ptr(offsetWords, static_cast<std::uint32_t>(n)));
}

void StructBuilder::set_struct(std::uint16_t index, const StructBuilder& target) {
    std::size_t slot = ptr_slot(index);
    std::int64_t offsetWords =
        (static_cast<std::int64_t>(target.data_offset()) - static_cast<std::int64_t>(slot) - 8) / 8;
    m_->write_ptr_raw(slot, make_struct_ptr(offsetWords, target.data_words(), target.ptr_count()));
}

// --- Reader ----------------------------------------------------------------

bool Reader::read_word(std::size_t off, std::uint64_t& v) const {
    if (off + 8 > size_) return false;
    v = rd_le64(base_ + off);
    return true;
}

bool Reader::root(std::size_t& dataOff, std::uint16_t& dataWords, std::uint16_t& ptrCount) const {
    std::uint64_t p = 0;
    if (!read_word(0, p)) return false;
    if ((p & 0x3) != 0) return false;  // must be a struct pointer

    std::uint32_t raw = static_cast<std::uint32_t>((p >> 2) & 0x3FFFFFFFu);
    // sign-extend the 30-bit signed offset
    std::int32_t offWords = static_cast<std::int32_t>(raw << 2) >> 2;
    dataWords = static_cast<std::uint16_t>((p >> 32) & 0xFFFF);
    ptrCount = static_cast<std::uint16_t>((p >> 48) & 0xFFFF);

    std::int64_t target = 8 + static_cast<std::int64_t>(offWords) * 8;
    if (target < 0 || static_cast<std::size_t>(target) + 8 > size_) return false;
    dataOff = static_cast<std::size_t>(target);
    return true;
}

bool Reader::read_struct_ptr(std::size_t ptrSlot, std::size_t& dataOff) const {
    std::uint64_t p = 0;
    if (!read_word(ptrSlot, p)) return false;
    if ((p & 0x3) != 0) return false;
    std::uint32_t raw = static_cast<std::uint32_t>((p >> 2) & 0x3FFFFFFFu);
    std::int32_t offWords = static_cast<std::int32_t>(raw << 2) >> 2;
    std::int64_t target = static_cast<std::int64_t>(ptrSlot) + 8 +
                          static_cast<std::int64_t>(offWords) * 8;
    if (target < 0 || static_cast<std::size_t>(target) + 8 > size_) return false;
    dataOff = static_cast<std::size_t>(target);
    return true;
}

bool Reader::read_struct_ptr(std::size_t ptrSlot, std::size_t& dataOff, std::uint16_t& dataWords,
                            std::uint16_t& ptrCount, std::size_t& ptrOff) const {
    std::uint64_t p = 0;
    if (!read_word(ptrSlot, p)) return false;
    if ((p & 0x3) != 0) return false;
    dataWords = static_cast<std::uint16_t>((p >> 32) & 0xFFFF);
    ptrCount = static_cast<std::uint16_t>((p >> 48) & 0xFFFF);
    std::uint32_t raw = static_cast<std::uint32_t>((p >> 2) & 0x3FFFFFFFu);
    std::int32_t offWords = static_cast<std::int32_t>(raw << 2) >> 2;
    std::int64_t target = static_cast<std::int64_t>(ptrSlot) + 8 +
                          static_cast<std::int64_t>(offWords) * 8;
    if (target < 0) return false;
    std::size_t content = static_cast<std::size_t>(target);
    std::size_t need = static_cast<std::size_t>(dataWords) * 8 +
                       static_cast<std::size_t>(ptrCount) * 8;
    if (content + need > size_) return false;
    dataOff = content;
    ptrOff = content + static_cast<std::size_t>(dataWords) * 8;
    return true;
}

bool Reader::read_u64(std::size_t off, std::uint64_t& v) const { return read_word(off, v); }
bool Reader::read_u32(std::size_t off, std::uint32_t& v) const {
    if (off + 4 > size_) return false;
    v = rd_le32(base_ + off);
    return true;
}
bool Reader::read_u16(std::size_t off, std::uint16_t& v) const {
    if (off + 2 > size_) return false;
    v = rd_le16(base_ + off);
    return true;
}

bool Reader::list_ptr(std::size_t ptrSlot, std::size_t& dataOff, std::size_t& count) const {
    std::uint64_t p = 0;
    if (!read_word(ptrSlot, p)) return false;
    if ((p & 0x3) != 1) return false;  // must be a list pointer
    std::uint32_t raw = static_cast<std::uint32_t>((p >> 2) & 0x3FFFFFFFu);
    std::int32_t offWords = static_cast<std::int32_t>(raw << 2) >> 2;
    // elementSize occupies bits 32..34; the element count starts at bit 35.
    std::uint32_t elemSize = static_cast<std::uint32_t>((p >> 32) & 0x7);
    count = static_cast<std::size_t>((p >> 35) & 0x1FFFFFFFu);
    if (elemSize != 2) return false;  // not a byte list
    std::int64_t target = static_cast<std::int64_t>(ptrSlot) + 8 +
                          static_cast<std::int64_t>(offWords) * 8;
    if (target < 0 || static_cast<std::size_t>(target) + count > size_) return false;
    dataOff = static_cast<std::size_t>(target);
    return true;
}

bool Reader::read_text(std::size_t ptrSlot, std::string& out) const {
    std::size_t off = 0, count = 0;
    if (!list_ptr(ptrSlot, off, count)) return false;
    if (count == 0) { out.clear(); return true; }
    out.assign(reinterpret_cast<const char*>(base_ + off), count - 1);
    return true;
}

bool Reader::read_blob(std::size_t ptrSlot, std::vector<std::uint8_t>& out) const {
    std::size_t off = 0, count = 0;
    if (!list_ptr(ptrSlot, off, count)) return false;
    out.assign(base_ + off, base_ + off + count);
    return true;
}

bool Reader::read_bytes(std::size_t ptrSlot, const std::uint8_t*& data, std::size_t& len) const {
    std::size_t off = 0, count = 0;
    if (!list_ptr(ptrSlot, off, count)) return false;
    data = base_ + off;
    len = count;
    return true;
}

} // namespace bpb::capnp
