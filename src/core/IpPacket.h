#ifndef PROCPCAP_IPPACKET_H
#define PROCPCAP_IPPACKET_H

#include "core/FlowTable.h"

#include <array>
#include <cstddef>
#include <cstdint>

namespace procpcap {

// The fields pulled out of a bare IP packet: enough to build a 5-tuple and to
// find the transport payload for the entropy calculation.
struct ParsedPacket {
    bool valid = false;
    bool v6 = false;
    uint8_t protocol = 0;
    std::array<uint8_t, 16> src{};
    std::array<uint8_t, 16> dst{};
    uint16_t srcPort = 0; // host order; 0 unless TCP or UDP
    uint16_t dstPort = 0;
    size_t payloadOffset = 0; // byte offset of the transport payload, 0 if none
    size_t payloadLength = 0;
};

// Parse a bare IPv4 or IPv6 packet (no link-layer header), as WinDivert delivers
// on the NETWORK layer. Returns a ParsedPacket with valid=false on anything too
// short or malformed. IPv6 extension headers up to the transport header are
// skipped; unknown transports parse the addresses but leave the ports at zero.
ParsedPacket parseIp(const uint8_t* data, size_t len);

// Turn a parsed packet into a 5-tuple from the local host's point of view. An
// outbound packet's source is local; an inbound packet's source is remote.
FiveTuple tupleFromPacket(const ParsedPacket& p, bool outbound);

} // namespace procpcap

#endif // PROCPCAP_IPPACKET_H
