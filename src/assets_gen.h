#pragma once
#include <cstddef>

namespace bpb::assets {

// Returns the embedded page bytes ("panel", "login", "error") or nullptr.
const char* page(const char* name, std::size_t& len);

// Embedded favicon bytes.
const char* icon(std::size_t& len);

} // namespace bpb::assets
