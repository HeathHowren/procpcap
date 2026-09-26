#ifndef PROCPCAP_PCAPNG_H
#define PROCPCAP_PCAPNG_H

#include <cstdint>
#include <string>
#include <vector>

namespace procpcap {

// LINKTYPE_RAW. The block body is a bare IP packet with no link-layer header,
// which is exactly what WinDivert hands back on the NETWORK layer. Wireshark
// reads the first nibble to tell IPv4 from IPv6.
constexpr uint16_t kLinkTypeRaw = 101;

// The default snap length written into the interface block. WinDivert reassembles
// to full packets, so nothing is truncated in practice; this is the advertised
// maximum.
constexpr uint32_t kDefaultSnapLen = 262144;

// Writes pcapng blocks into byte buffers. The writer holds no file handle: the
// caller decides where the bytes go (a file, or stdout for a Wireshark pipe),
// which is what makes it testable without a driver or a disk.
//
// Layout follows the pcapng specification: a Section Header Block and one
// Interface Description Block up front, then one Enhanced Packet Block per
// captured packet. Every packet block carries an opt_comment (option code 1)
// holding the owning PID and process name.
class PcapNgWriter {
public:
    // appName fills the Section Header Block's shb_userappl option, e.g.
    // "procpcap 1.0.0".
    explicit PcapNgWriter(std::string appName, uint32_t snapLen = kDefaultSnapLen);

    // The Section Header Block followed by one Interface Description Block. Emit
    // this once, before any packet block.
    std::vector<uint8_t> fileHeader() const;

    // One Enhanced Packet Block. tsMicros is microseconds since the Unix epoch
    // (the interface block advertises microsecond resolution). comment is copied
    // verbatim into opt_comment, e.g. "pid 1234 game.exe".
    std::vector<uint8_t> packetBlock(const uint8_t* packet, size_t packetLen, uint64_t tsMicros, const std::string& comment,
                                     uint32_t interfaceId = 0) const;

private:
    std::string appName_;
    uint32_t snapLen_;
};

} // namespace procpcap

#endif // PROCPCAP_PCAPNG_H
