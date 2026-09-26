#include "core/IpPacket.h"

namespace procpcap {

namespace {

uint16_t readBE16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }

// Fill the transport ports for TCP and UDP. Both carry source and destination
// ports as the first two 16-bit big-endian fields, so one path handles both.
void fillPorts(ParsedPacket& out, const uint8_t* data, size_t len, size_t transportOffset) {
    if (out.protocol != kProtoTcp && out.protocol != kProtoUdp)
        return;
    if (transportOffset + 4 > len)
        return;
    out.srcPort = readBE16(data + transportOffset);
    out.dstPort = readBE16(data + transportOffset + 2);

    if (out.protocol == kProtoUdp) {
        // UDP header is a fixed 8 bytes.
        if (transportOffset + 8 <= len) {
            out.payloadOffset = transportOffset + 8;
            out.payloadLength = len - out.payloadOffset;
        }
    } else {
        // TCP data offset is the high nibble of byte 12, in 32-bit words.
        if (transportOffset + 13 <= len) {
            size_t dataOffsetWords = (data[transportOffset + 12] >> 4) & 0x0F;
            size_t headerLen = dataOffsetWords * 4;
            if (headerLen >= 20 && transportOffset + headerLen <= len) {
                out.payloadOffset = transportOffset + headerLen;
                out.payloadLength = len - out.payloadOffset;
            }
        }
    }
}

ParsedPacket parseV4(const uint8_t* data, size_t len) {
    ParsedPacket out;
    if (len < 20)
        return out;
    size_t ihl = (data[0] & 0x0F) * 4u;
    if (ihl < 20 || ihl > len)
        return out;
    out.v6 = false;
    out.protocol = data[9];
    for (int i = 0; i < 4; ++i) {
        out.src[static_cast<size_t>(i)] = data[12 + i];
        out.dst[static_cast<size_t>(i)] = data[16 + i];
    }
    fillPorts(out, data, len, ihl);
    out.valid = true;
    return out;
}

ParsedPacket parseV6(const uint8_t* data, size_t len) {
    ParsedPacket out;
    if (len < 40)
        return out;
    out.v6 = true;
    uint8_t nextHeader = data[6];
    for (int i = 0; i < 16; ++i) {
        out.src[static_cast<size_t>(i)] = data[8 + i];
        out.dst[static_cast<size_t>(i)] = data[24 + i];
    }
    // Walk the well-known IPv6 extension headers to reach the transport header.
    size_t offset = 40;
    for (int guard = 0; guard < 8; ++guard) {
        switch (nextHeader) {
        case 0:  // Hop-by-Hop Options
        case 43: // Routing
        case 60: // Destination Options
        case 51: // Authentication Header (length counted in 4-byte units, +2)
        {
            if (offset + 2 > len)
                return out;
            size_t extLen = (nextHeader == 51) ? (static_cast<size_t>(data[offset + 1]) + 2) * 4 : (static_cast<size_t>(data[offset + 1]) + 1) * 8;
            nextHeader = data[offset];
            offset += extLen;
            if (offset > len)
                return out;
            break;
        }
        default:
            out.protocol = nextHeader;
            fillPorts(out, data, len, offset);
            out.valid = true;
            return out;
        }
    }
    return out;
}

} // namespace

ParsedPacket parseIp(const uint8_t* data, size_t len) {
    if (data == nullptr || len < 1)
        return ParsedPacket{};
    uint8_t version = (data[0] >> 4) & 0x0F;
    if (version == 4)
        return parseV4(data, len);
    if (version == 6)
        return parseV6(data, len);
    return ParsedPacket{};
}

FiveTuple tupleFromPacket(const ParsedPacket& p, bool outbound) {
    FiveTuple t;
    t.v6 = p.v6;
    t.protocol = p.protocol;
    if (outbound) {
        t.local.addr = p.src;
        t.local.port = p.srcPort;
        t.remote.addr = p.dst;
        t.remote.port = p.dstPort;
    } else {
        t.local.addr = p.dst;
        t.local.port = p.dstPort;
        t.remote.addr = p.src;
        t.remote.port = p.srcPort;
    }
    return t;
}

} // namespace procpcap
