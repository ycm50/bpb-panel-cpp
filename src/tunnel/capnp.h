#pragma once
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace bpb::capnp {

// Minimal Cap'n Proto wire-format codec, scoped to what the Cloudflare tunnel
// RPC needs (structs with data + pointer sections, text, data blobs).
//
// Layout reminder: a *struct pointer* carries the field counts and the distance
// to the struct's content. The content itself is just [data][pointers]; there is
// no header at the target.

class Message;

class StructBuilder {
public:
    StructBuilder() = default;
    StructBuilder(Message* m, std::size_t dataOff, std::uint16_t dataWords, std::uint16_t ptrCount)
        : m_(m), dataOff_(dataOff), dataWords_(dataWords), ptrCount_(ptrCount) {}

    void set_u8(std::uint16_t field, std::uint8_t v);
    void set_u16(std::uint16_t field, std::uint16_t v);
    void set_u32(std::uint16_t field, std::uint32_t v);
    void set_u64(std::uint16_t field, std::uint64_t v);
    void set_bool(std::uint16_t bit, bool v);

    // Writes a 16-bit union discriminant at an arbitrary BIT offset, matching
    // capnp's generated setDataField<Which>(bounded<N>() * ELEMENTS, v).
    // N is the bit offset, not a byte offset.
    void set_union_tag(std::uint16_t bitOffset, std::uint16_t value);

    void set_text(std::uint16_t index, const std::string& s);
    void set_data(std::uint16_t index, const void* d, std::size_t n);
    // Points ptr[index] at another struct built in the same message.
    void set_struct(std::uint16_t index, const StructBuilder& target);

    std::size_t data_offset() const { return dataOff_; }
    std::uint16_t data_words() const { return dataWords_; }
    std::uint16_t ptr_count() const { return ptrCount_; }

private:
    std::size_t ptr_slot(std::uint16_t index) const;

    Message* m_ = nullptr;
    std::size_t dataOff_ = 0;
    std::uint16_t dataWords_ = 0;
    std::uint16_t ptrCount_ = 0;
};

class Message {
public:
    explicit Message(std::size_t reserve = 1024);

    // Allocates a struct (data + pointer sections) and returns a builder.
    StructBuilder alloc_struct(std::uint16_t dataWords, std::uint16_t ptrCount);

    // Declares the root struct; must be called once.
    void set_root(const StructBuilder& s) { root_ = s; hasRoot_ = true; }

    // Serialises with the segment table; the root pointer is emitted at byte 0
    // of the segment.
    std::vector<std::uint8_t> finish() const;

    std::vector<std::uint8_t>& arena() { return arena_; }
    const std::vector<std::uint8_t>& arena() const { return arena_; }

    void write_u16(std::size_t off, std::uint16_t v);
    void write_u32(std::size_t off, std::uint32_t v);
    void write_u64(std::size_t off, std::uint64_t v);
    void write_bool(std::size_t off, bool v);
    void write_ptr_raw(std::size_t off, std::uint64_t v);

    std::size_t allocate(std::size_t bytes, std::size_t align = 8);

private:
    std::vector<std::uint8_t> arena_;   // segment body; root pointer written at offset 0
    StructBuilder root_;
    bool hasRoot_ = false;
};

class Reader {
public:
    // Accepts the *framed* message produced by Message::finish(); the 8-byte
    // segment table is skipped so offsets are relative to the segment body.
    Reader(const std::uint8_t* base, std::size_t size) : base_(base), size_(size) {
        if (size_ >= 8) {
            base_ += 8;
            size_ -= 8;
        }
    }

    // Reads the root struct pointer (at segment offset 0) and returns the
    // content offset plus its field counts.
    bool root(std::size_t& dataOff, std::uint16_t& dataWords, std::uint16_t& ptrCount) const;

    // Resolves ptrSlot at absolute offset to a struct's content offset.
    bool read_struct_ptr(std::size_t ptrSlot, std::size_t& dataOff) const;

    // Resolves ptrSlot to a struct, also returning the field counts carried by
    // the pointer (a struct's content has no inline header).
    bool read_struct_ptr(std::size_t ptrSlot, std::size_t& dataOff, std::uint16_t& dataWords,
                         std::uint16_t& ptrCount, std::size_t& ptrOff) const;

    bool read_u64(std::size_t off, std::uint64_t& v) const;
    bool read_u32(std::size_t off, std::uint32_t& v) const;
    bool read_u16(std::size_t off, std::uint16_t& v) const;

    bool read_text(std::size_t ptrSlot, std::string& out) const;
    bool read_blob(std::size_t ptrSlot, std::vector<std::uint8_t>& out) const;

    // Byte-list access without copying (used for streaming data).
    bool read_bytes(std::size_t ptrSlot, const std::uint8_t*& data, std::size_t& len) const;

    std::size_t size() const { return size_; }

private:
    bool read_word(std::size_t off, std::uint64_t& v) const;
    bool list_ptr(std::size_t ptrSlot, std::size_t& dataOff, std::size_t& count) const;

    const std::uint8_t* base_;
    std::size_t size_;
};

} // namespace bpb::capnp
