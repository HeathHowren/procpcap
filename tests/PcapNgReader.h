#ifndef PROCPCAP_TESTS_PCAPNGREADER_H
#define PROCPCAP_TESTS_PCAPNGREADER_H

// A minimal, read-only pcapng walker for the tests and the synth tool. It is not
// part of the product; it exists to prove the writer's output parses back to the
// packets and comments that went in. It handles only the little-endian layout
// procpcap writes.

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace procpcap_test {

struct ReadPacket {
    uint32_t interfaceId = 0;
    uint64_t tsMicros = 0;
    std::vector<uint8_t> data;
    std::string comment;
};

struct ReadResult {
    bool ok = false;
    std::string error;
    uint16_t linkType = 0;
    uint32_t snapLen = 0;
    std::string appName;
    std::vector<ReadPacket> packets;
};

namespace detail {

inline uint16_t rdU16(const uint8_t* p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
inline uint32_t rdU32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) | (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}
inline uint64_t rdU64(const uint8_t* p) { return rdU32(p) | (static_cast<uint64_t>(rdU32(p + 4)) << 32); }
inline size_t roundUp4(size_t n) { return (n + 3) & ~static_cast<size_t>(3); }

// Walk the options area (from `off`, length `len`) invoking fn(code, ptr, len).
template <typename Fn> void forEachOption(const uint8_t* base, size_t off, size_t len, Fn&& fn) {
    size_t pos = off;
    const size_t end = off + len;
    while (pos + 4 <= end) {
        uint16_t code = rdU16(base + pos);
        uint16_t olen = rdU16(base + pos + 2);
        if (code == 0) // opt_endofopt
            break;
        if (pos + 4 + olen > end)
            break;
        fn(code, base + pos + 4, olen);
        pos += 4 + roundUp4(olen);
    }
}

} // namespace detail

inline ReadResult readPcapng(const std::vector<uint8_t>& buf) {
    using namespace detail;
    ReadResult r;
    size_t pos = 0;
    bool haveShb = false;
    bool haveIdb = false;

    while (pos + 8 <= buf.size()) {
        uint32_t type = rdU32(&buf[pos]);
        uint32_t total = rdU32(&buf[pos + 4]);
        if (total < 12 || pos + total > buf.size()) {
            r.error = "block length out of range";
            return r;
        }
        uint32_t trailing = rdU32(&buf[pos + total - 4]);
        if (trailing != total) {
            r.error = "block length mismatch (head vs tail)";
            return r;
        }

        if (type == 0x0A0D0D0A) { // Section Header Block
            if (rdU32(&buf[pos + 8]) != 0x1A2B3C4D) {
                r.error = "bad byte-order magic";
                return r;
            }
            const size_t optOff = pos + 24;
            if (optOff <= pos + total - 4) {
                forEachOption(buf.data(), optOff, (pos + total - 4) - optOff, [&](uint16_t code, const uint8_t* p, uint16_t len) {
                    if (code == 4)
                        r.appName.assign(reinterpret_cast<const char*>(p), len);
                });
            }
            haveShb = true;
        } else if (type == 0x00000001) { // Interface Description Block
            r.linkType = rdU16(&buf[pos + 8]);
            r.snapLen = rdU32(&buf[pos + 12]);
            haveIdb = true;
        } else if (type == 0x00000006) { // Enhanced Packet Block
            ReadPacket pkt;
            pkt.interfaceId = rdU32(&buf[pos + 8]);
            uint64_t high = rdU32(&buf[pos + 12]);
            uint64_t low = rdU32(&buf[pos + 16]);
            pkt.tsMicros = (high << 32) | low;
            uint32_t capLen = rdU32(&buf[pos + 20]);
            const size_t dataOff = pos + 28;
            if (dataOff + capLen > pos + total - 4) {
                r.error = "packet data exceeds block";
                return r;
            }
            pkt.data.assign(&buf[dataOff], &buf[dataOff] + capLen);
            const size_t optOff = dataOff + roundUp4(capLen);
            if (optOff <= pos + total - 4) {
                forEachOption(buf.data(), optOff, (pos + total - 4) - optOff, [&](uint16_t code, const uint8_t* p, uint16_t len) {
                    if (code == 1)
                        pkt.comment.assign(reinterpret_cast<const char*>(p), len);
                });
            }
            r.packets.push_back(std::move(pkt));
        }
        // Unknown block types are skipped by their length, per the spec.

        pos += total;
    }

    if (!haveShb || !haveIdb) {
        r.error = "missing section header or interface block";
        return r;
    }
    r.ok = true;
    return r;
}

} // namespace procpcap_test

#endif // PROCPCAP_TESTS_PCAPNGREADER_H
