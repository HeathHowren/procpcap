#include <catch2/catch_test_macros.hpp>

#include "core/IpPacket.h"

#include <vector>

using namespace procpcap;

namespace {

// Build a bare IPv4 + UDP packet. Ports and addresses go on the wire big-endian.
std::vector<uint8_t> ipv4Udp(const uint8_t src[4], const uint8_t dst[4], uint16_t sport, uint16_t dport,
                             const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> p(20 + 8 + payload.size(), 0);
    p[0] = 0x45; // version 4, IHL 5
    p[9] = kProtoUdp;
    for (int i = 0; i < 4; ++i) {
        p[12 + i] = src[i];
        p[16 + i] = dst[i];
    }
    p[20] = static_cast<uint8_t>(sport >> 8);
    p[21] = static_cast<uint8_t>(sport & 0xFF);
    p[22] = static_cast<uint8_t>(dport >> 8);
    p[23] = static_cast<uint8_t>(dport & 0xFF);
    for (size_t i = 0; i < payload.size(); ++i)
        p[28 + i] = payload[i];
    return p;
}

// Build a bare IPv4 + TCP packet with a 20-byte TCP header (data offset 5).
std::vector<uint8_t> ipv4Tcp(const uint8_t src[4], const uint8_t dst[4], uint16_t sport, uint16_t dport,
                             const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> p(20 + 20 + payload.size(), 0);
    p[0] = 0x45;
    p[9] = kProtoTcp;
    for (int i = 0; i < 4; ++i) {
        p[12 + i] = src[i];
        p[16 + i] = dst[i];
    }
    p[20] = static_cast<uint8_t>(sport >> 8);
    p[21] = static_cast<uint8_t>(sport & 0xFF);
    p[22] = static_cast<uint8_t>(dport >> 8);
    p[23] = static_cast<uint8_t>(dport & 0xFF);
    p[32] = 0x50; // data offset 5 words (20 bytes) in the high nibble
    for (size_t i = 0; i < payload.size(); ++i)
        p[40 + i] = payload[i];
    return p;
}

} // namespace

TEST_CASE("parse an IPv4 UDP packet", "[ippacket]") {
    const uint8_t src[4] = {192, 168, 0, 2};
    const uint8_t dst[4] = {8, 8, 8, 8};
    auto p = ipv4Udp(src, dst, 50000, 53, {0xDE, 0xAD, 0xBE, 0xEF});

    ParsedPacket r = parseIp(p.data(), p.size());
    REQUIRE(r.valid);
    REQUIRE_FALSE(r.v6);
    REQUIRE(r.protocol == kProtoUdp);
    REQUIRE(r.srcPort == 50000);
    REQUIRE(r.dstPort == 53);
    REQUIRE(r.payloadOffset == 28);
    REQUIRE(r.payloadLength == 4);
    REQUIRE(r.src[0] == 192);
    REQUIRE(r.dst[0] == 8);
}

TEST_CASE("parse an IPv4 TCP packet and locate its payload", "[ippacket]") {
    const uint8_t src[4] = {10, 0, 0, 5};
    const uint8_t dst[4] = {93, 184, 216, 34};
    auto p = ipv4Tcp(src, dst, 44444, 443, {1, 2, 3});
    ParsedPacket r = parseIp(p.data(), p.size());
    REQUIRE(r.valid);
    REQUIRE(r.protocol == kProtoTcp);
    REQUIRE(r.dstPort == 443);
    REQUIRE(r.payloadOffset == 40);
    REQUIRE(r.payloadLength == 3);
}

TEST_CASE("outbound and inbound map source and destination to local and remote", "[ippacket]") {
    const uint8_t src[4] = {192, 168, 0, 2};
    const uint8_t dst[4] = {8, 8, 8, 8};
    auto p = ipv4Udp(src, dst, 50000, 53, {});
    ParsedPacket r = parseIp(p.data(), p.size());

    FiveTuple out = tupleFromPacket(r, /*outbound=*/true);
    REQUIRE(out.local.port == 50000);
    REQUIRE(out.remote.port == 53);
    REQUIRE(out.local.addr[0] == 192);
    REQUIRE(out.remote.addr[0] == 8);

    FiveTuple in = tupleFromPacket(r, /*outbound=*/false);
    REQUIRE(in.local.port == 53);
    REQUIRE(in.remote.port == 50000);
    REQUIRE(in.local.addr[0] == 8);
    REQUIRE(in.remote.addr[0] == 192);
}

TEST_CASE("parse an IPv6 UDP packet", "[ippacket]") {
    std::vector<uint8_t> p(40 + 8, 0);
    p[0] = 0x60;        // version 6
    p[6] = kProtoUdp;   // next header
    p[8] = 0x20;        // src addr first byte
    p[24] = 0x20;       // dst addr first byte
    p[40] = 0x30;       // sport high
    p[41] = 0x39;       // sport low -> 12345
    p[42] = 0x00;
    p[43] = 0x35;       // dport 53
    ParsedPacket r = parseIp(p.data(), p.size());
    REQUIRE(r.valid);
    REQUIRE(r.v6);
    REQUIRE(r.protocol == kProtoUdp);
    REQUIRE(r.srcPort == 12345);
    REQUIRE(r.dstPort == 53);
}

TEST_CASE("IPv6 hop-by-hop extension header is skipped to reach the transport", "[ippacket]") {
    // 40-byte base + 8-byte hop-by-hop option + 8-byte UDP header.
    std::vector<uint8_t> p(40 + 8 + 8, 0);
    p[0] = 0x60;
    p[6] = 0;         // next header = Hop-by-Hop Options
    p[40] = kProtoUdp; // hop-by-hop: next header is UDP
    p[41] = 0;         // hop-by-hop length: 0 -> (0+1)*8 = 8 bytes
    p[48] = 0x00;
    p[49] = 0x50;      // sport 80
    p[50] = 0x01;
    p[51] = 0xBB;      // dport 443
    ParsedPacket r = parseIp(p.data(), p.size());
    REQUIRE(r.valid);
    REQUIRE(r.protocol == kProtoUdp);
    REQUIRE(r.srcPort == 80);
    REQUIRE(r.dstPort == 443);
}

TEST_CASE("malformed and truncated packets are rejected", "[ippacket]") {
    REQUIRE_FALSE(parseIp(nullptr, 0).valid);
    const uint8_t tooShort[3] = {0x45, 0, 0};
    REQUIRE_FALSE(parseIp(tooShort, sizeof(tooShort)).valid);
    const uint8_t badVersion[20] = {0x35}; // version 3
    REQUIRE_FALSE(parseIp(badVersion, sizeof(badVersion)).valid);
    // IHL claims 60 bytes but only 20 are present.
    std::vector<uint8_t> shortIhl(20, 0);
    shortIhl[0] = 0x4F; // version 4, IHL 15 -> 60 bytes
    REQUIRE_FALSE(parseIp(shortIhl.data(), shortIhl.size()).valid);
}
