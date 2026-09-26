#include "core/PcapNg.h"

#include "core/ByteWriter.h"

#include <utility>

namespace procpcap {

namespace {

// Block type constants from the pcapng specification.
constexpr uint32_t kBlockShb = 0x0A0D0D0A;
constexpr uint32_t kBlockIdb = 0x00000001;
constexpr uint32_t kBlockEpb = 0x00000006;

constexpr uint32_t kByteOrderMagic = 0x1A2B3C4D;

// Option codes.
constexpr uint16_t kOptEndOfOpt = 0;   // any block
constexpr uint16_t kOptComment = 1;    // any block: opt_comment
constexpr uint16_t kOptShbUserAppl = 4;
constexpr uint16_t kOptIfTsResol = 9;

// Append one option (code, length, value, padding). A zero-length value still
// writes the 4-byte header, which the padding rules require.
void putOption(ByteWriter& w, uint16_t code, const uint8_t* value, uint16_t len) {
    w.u16(code);
    w.u16(len);
    if (len != 0)
        w.bytes(value, len);
    w.pad4();
}

void putStringOption(ByteWriter& w, uint16_t code, const std::string& value) {
    // pcapng option lengths are 16-bit; clamp defensively so a pathologically
    // long process path can never corrupt the length field.
    uint16_t len = value.size() > 0xFFFF ? 0xFFFF : static_cast<uint16_t>(value.size());
    putOption(w, code, reinterpret_cast<const uint8_t*>(value.data()), len);
}

} // namespace

PcapNgWriter::PcapNgWriter(std::string appName, uint32_t snapLen) : appName_(std::move(appName)), snapLen_(snapLen) {}

std::vector<uint8_t> PcapNgWriter::fileHeader() const {
    ByteWriter w;

    // ---- Section Header Block ----
    w.u32(kBlockShb);
    const size_t shbLenAt = w.size();
    w.u32(0); // total length, backfilled
    w.u32(kByteOrderMagic);
    w.u16(1); // version major
    w.u16(0); // version minor
    w.u64(0xFFFFFFFFFFFFFFFFULL); // section length: unknown
    putStringOption(w, kOptShbUserAppl, appName_);
    putOption(w, kOptEndOfOpt, nullptr, 0);
    w.u32(0); // trailing total length, backfilled
    const uint32_t shbTotal = static_cast<uint32_t>(w.size() - (shbLenAt - 4));
    w.patchU32(shbLenAt, shbTotal);
    w.patchU32(w.size() - 4, shbTotal);

    // ---- Interface Description Block ----
    w.u32(kBlockIdb);
    const size_t idbLenAt = w.size();
    w.u32(0); // total length, backfilled
    w.u16(kLinkTypeRaw);
    w.u16(0); // reserved
    w.u32(snapLen_);
    // if_tsresol = 6 means timestamps are in units of 10^-6 s (microseconds).
    const uint8_t tsResol = 6;
    putOption(w, kOptIfTsResol, &tsResol, 1);
    putOption(w, kOptEndOfOpt, nullptr, 0);
    w.u32(0); // trailing total length, backfilled
    const uint32_t idbTotal = static_cast<uint32_t>(w.size() - (idbLenAt - 4));
    w.patchU32(idbLenAt, idbTotal);
    w.patchU32(w.size() - 4, idbTotal);

    return w.take();
}

std::vector<uint8_t> PcapNgWriter::packetBlock(const uint8_t* packet, size_t packetLen, uint64_t tsMicros, const std::string& comment,
                                               uint32_t interfaceId) const {
    ByteWriter w;

    w.u32(kBlockEpb);
    const size_t lenAt = w.size();
    w.u32(0); // total length, backfilled
    w.u32(interfaceId);
    w.u32(static_cast<uint32_t>(tsMicros >> 32));        // timestamp high
    w.u32(static_cast<uint32_t>(tsMicros & 0xFFFFFFFF)); // timestamp low
    w.u32(static_cast<uint32_t>(packetLen));             // captured length
    w.u32(static_cast<uint32_t>(packetLen));             // original length
    if (packetLen != 0)
        w.bytes(packet, packetLen);
    w.pad4();
    if (!comment.empty())
        putStringOption(w, kOptComment, comment);
    putOption(w, kOptEndOfOpt, nullptr, 0);
    w.u32(0); // trailing total length, backfilled
    const uint32_t total = static_cast<uint32_t>(w.size() - (lenAt - 4));
    w.patchU32(lenAt, total);
    w.patchU32(w.size() - 4, total);

    return w.take();
}

} // namespace procpcap
