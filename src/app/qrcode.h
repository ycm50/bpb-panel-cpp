#pragma once
#include "http/http.h"

#include <functional>
#include <string>

namespace bpb {

// Renders a QR code as a PNG (RGBA, 8x scale, 4 modules margin) like the TS panel did.
bool generate_qr_png(const std::string& data, std::string& png, std::string& error);

namespace app {

// GET <securePath>/qrcode?data=...
//
// Lives here rather than as an App method so the routing decision and the PNG
// encoder share one file: the interesting parts of this route are the origin
// check and the encoding, neither of which needs the store.
//
// render_error lets the caller supply the panel's own 404 page. Passing it in
// (instead of including app.h) keeps this module free of App and avoids a
// circular dependency.
http::Response qrcode_route(
    const http::Request& req,
    const std::function<http::Response(int, const std::string&)>& render_error);

} // namespace app
} // namespace bpb
