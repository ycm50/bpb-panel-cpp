#pragma once
#include <string>
#include <utility>
#include <vector>

namespace bpb {

// Minimal ZIP writer (stored, no compression) - used for WireGuard/Amnezia config bundles.
std::string zip_store(const std::vector<std::pair<std::string, std::string>>& files);

} // namespace bpb
