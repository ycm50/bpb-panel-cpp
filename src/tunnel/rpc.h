#pragma once
#include <cstdint>
#include <cstddef>
#include <functional>
#include <string>
#include <vector>

#include "tunnel/capnp.h"

namespace bpb::tunnel {

// Minimal Cap'n Proto RPC (level 0) for the Cloudflare tunnel control stream.
//
// Framing on the byte stream: 4-byte little-endian length + one capnp message.
//
// Message union discriminants (rpc.capnp):
//   abort=1 call=2 return_=3 finish=4 bootstrap=8

enum RpcKind : std::uint16_t {
    kRpcUnimplemented = 0,
    kRpcAbort = 1,
    kRpcCall = 2,
    kRpcReturn = 3,
    kRpcFinish = 4,
    kRpcBootstrap = 8,
};

// Interface / method ids (tunnelrpc.capnp).
inline constexpr std::uint64_t kRegistrationServerId = 0xf71695ec7fe85497ull;
inline constexpr std::uint16_t kMethodRegisterConnection = 0;
inline constexpr std::uint16_t kMethodUnregisterConnection = 1;
inline constexpr std::uint16_t kMethodUpdateLocalConfiguration = 2;

class RpcStream {
public:
    // Message{bootstrap}; returns the framed bytes ready for the stream.
    static std::vector<std::uint8_t> encode_bootstrap(std::uint32_t questionId);

    // Message{call}. The caller supplies a builder that creates the method's
    // params struct *inside the same message*, so all internal pointers stay
    // valid. Returns the framed bytes.
    using ParamsBuilder = std::function<capnp::StructBuilder(capnp::Message&)>;
    // Targets a capability via MessageTarget.importedCap. importId is the
    // ExportId the peer advertised in its capTable (0 for the bootstrap cap).
    static std::vector<std::uint8_t> encode_call(std::uint32_t questionId,
                                                 std::uint32_t importId,
                                                 std::uint64_t interfaceId,
                                                 std::uint16_t methodId,
                                                 const ParamsBuilder& buildParams);

    // Message{finish} acknowledging a return.
    static std::vector<std::uint8_t> encode_finish(std::uint32_t questionId, bool releaseResultCaps);

    // Parses an unframed RPC message header (kind + id).
    static bool peek(const std::uint8_t* msg, std::size_t len, std::uint16_t& kind,
                     std::uint32_t& id);

    static std::vector<std::uint8_t> frame(const std::vector<std::uint8_t>& msg);
};

// Reads the payload struct of a Return message into out (raw struct bytes plus
// the offset inside msg). Returns false if the message is not a Return or is
// malformed; error carries a short reason.
bool rpc_return_payload(const std::uint8_t* msg, std::size_t len, std::size_t& structOff,
                        std::uint16_t& dataWords, std::uint16_t& ptrCount, std::string& error);

// Locates the first CapDescriptor in a Return's results.capTable that was
// exported by the peer (senderHosted) and yields its ExportId, which is what an
// importedCap target must reference. Returns false when there is no such cap.
bool rpc_return_cap_export_id(const std::uint8_t* msg, std::size_t len, std::uint32_t& exportId,
                              std::string& error);

} // namespace bpb::tunnel
