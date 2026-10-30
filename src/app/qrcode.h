#pragma once
#include <string>

namespace bpb {

// Renders a QR code as a PNG (RGBA, 8x scale, 4 modules margin) like the TS panel did.
bool generate_qr_png(const std::string& data, std::string& png, std::string& error);

} // namespace bpb
