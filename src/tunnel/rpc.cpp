#include "tunnel/rpc.h"

#include <cstring>

namespace bpb::tunnel {

namespace {

// (no helpers needed; see frame())

} // namespace

std::vector<std::uint8_t> RpcStream::frame(const std::vector<std::uint8_t>& msg) {
    // capnp's rpc.StreamTransport writes raw messages back-to-back: each message
    // is self-delimiting thanks to its own segment table. There is NO length
    // prefix -- adding one makes the edge silently drop the message.
    return msg;
}

std::vector<std::uint8_t> RpcStream::encode_bootstrap(std::uint32_t questionId) {
    capnp::Message m(256);
    auto root = m.alloc_struct(1, 1);
    m.set_root(root);
    root.set_u16(0, kRpcBootstrap);

    // Bootstrap { questionId @0 :UInt32; deprecatedObjectId @1 :AnyPointer; }
    auto boot = m.alloc_struct(1, 1);
    boot.set_u32(0, questionId);
    root.set_struct(0, boot);

    return frame(m.finish());
}

std::vector<std::uint8_t> RpcStream::encode_call(std::uint32_t questionId,
                                                 std::uint32_t importId,
                                                 std::uint64_t interfaceId,
                                                 std::uint16_t methodId,
                                                 const ParamsBuilder& buildParams) {
    capnp::Message m(1024);
    auto root = m.alloc_struct(1, 1);
    m.set_root(root);
    root.set_u16(0, kRpcCall);

    // Call {
    //   questionId  @0 :UInt32      -> data word 0, bytes 0..3
    //   target      @1 :MessageTarget -> ptr 0
    //   interfaceId @2 :UInt64      -> data word 1
    //   methodId    @3 :UInt16      -> data word 0, bytes 4..5
    //   params      @4 :Payload     -> ptr 1
    // }
    auto call = m.alloc_struct(2, 2);
    root.set_struct(0, call);            // Message.call points at the Call struct
    call.set_u32(0, questionId);
    m.write_u16(call.data_offset() + 4, methodId);
    m.write_u64(call.data_offset() + 8, interfaceId);

    // MessageTarget { union { importedCap @0 :ImportId; promisedAnswer @1 :PromisedAnswer } }
    //
    // The edge's Bootstrap Return carries capTable[0].senderHosted = 0 (verified
    // with the official `capnp decode` tool), so the capability is addressable
    // as importedCap with ImportId 0.
    // The edge resolves promisedAnswer against its OWN answers table, which is
    // keyed by the question ids WE sent. Bootstrap used questionId 1, so the
    // pipelined call targets promisedAnswer{questionId=1}.
    auto target = m.alloc_struct(1, 1);
    // capnp's generated code uses setDataField<Which>(bounded<2>() * ELEMENTS),
    // i.e. element offset 2 of a uint16_t -> byte offset 4. The importedCap
    // member itself is a UInt32 at byte offset 0.
    target.set_u16(2, 1);                    // union tag = promisedAnswer
    auto promised = m.alloc_struct(1, 1);
    promised.set_u32(0, importId);           // bootstrap question id
    // transform: empty list (null pointer is accepted as empty).
    target.set_struct(0, promised);
    call.set_struct(0, target);

    // Payload { content @0 :AnyPointer; capTable @1 :List(CapDescriptor) }
    auto payload = m.alloc_struct(0, 2);
    call.set_struct(1, payload);

    // Build the params struct in the SAME message so internal offsets are valid,
    // then point Payload.content at it.
    auto params = buildParams(m);
    payload.set_struct(0, params);

    return frame(m.finish());
}

std::vector<std::uint8_t> RpcStream::encode_finish(std::uint32_t questionId,
                                                   bool releaseResultCaps) {
    capnp::Message m(128);
    auto root = m.alloc_struct(1, 1);
    m.set_root(root);
    root.set_u16(0, kRpcFinish);

    // Finish { questionId @0 :UInt32; releaseResultCaps @1 :Bool = true; }
    auto fin = m.alloc_struct(1, 0);
    fin.set_u32(0, questionId);
    fin.set_bool(4 * 8, releaseResultCaps);   // bool at byte 4
    root.set_struct(0, fin);

    return frame(m.finish());
}

bool RpcStream::peek(const std::uint8_t* msg, std::size_t len, std::uint16_t& kind,
                     std::uint32_t& id) {
    capnp::Reader rd(msg, len);
    std::size_t dataOff = 0;
    std::uint16_t dw = 0, pc = 0;
    if (!rd.root(dataOff, dw, pc)) return false;
    if (!rd.read_u16(dataOff, kind)) return false;

    std::size_t memberOff = 0;
    if (!rd.read_struct_ptr(dataOff + static_cast<std::size_t>(dw) * 8, memberOff)) {
        id = 0;
        return true;
    }
    if (!rd.read_u32(memberOff, id)) id = 0;
    return true;
}

bool rpc_return_payload(const std::uint8_t* msg, std::size_t len, std::size_t& structOff,
                        std::uint16_t& dataWords, std::uint16_t& ptrCount, std::string& error) {
    capnp::Reader rd(msg, len);
    std::size_t dataOff = 0;
    std::uint16_t dw = 0, pc = 0;
    if (!rd.root(dataOff, dw, pc)) {
        error = "bad capnp root";
        return false;
    }
    std::uint16_t kind = 0;
    if (!rd.read_u16(dataOff, kind)) {
        error = "no discriminant";
        return false;
    }
    if (kind != kRpcReturn) {
        error = "not a Return (kind=" + std::to_string(kind) + ")";
        return false;
    }

    // Return { answerId @0 :UInt32; releaseParamCaps @1 :Bool;
    //          results @2 :Payload; }
    //
    // The pointer at (dataOff + dw*8) points at the Return struct's *content*;
    // the field counts come from that pointer, so read them in the same call.
    std::size_t retOff = 0;        // Return struct content
    std::uint16_t rdw = 0, rpcnt = 0;
    std::size_t retPtrOff = 0;     // Return struct pointer section
    if (!rd.read_struct_ptr(dataOff + static_cast<std::size_t>(dw) * 8, retOff, rdw, rpcnt,
                            retPtrOff)) {
        error = "no Return struct";
        return false;
    }

    // results is pointer index 0 of the Return struct.
    std::size_t payloadOff = 0;
    std::uint16_t pdw = 0, ppc = 0;
    std::size_t payPtrOff = 0;
    if (rpcnt < 1) {
        error = "Return has no pointer section";
        return false;
    }
    if (!rd.read_struct_ptr(retPtrOff, payloadOff, pdw, ppc, payPtrOff)) {
        error = "Return has no results payload";
        return false;
    }

    // Payload.content is pointer index 0.
    if (ppc < 1) {
        error = "Payload has no content pointer";
        return false;
    }
    std::size_t contentOff = 0;
    std::uint16_t cdw = 0, cpc = 0;
    std::size_t contentPtrOff = 0;
    if (!rd.read_struct_ptr(payPtrOff, contentOff, cdw, cpc, contentPtrOff)) {
        error = "empty results content";
        return false;
    }
    structOff = contentOff;
    dataWords = cdw;
    ptrCount = cpc;
    return true;
}

} // namespace bpb::tunnel
