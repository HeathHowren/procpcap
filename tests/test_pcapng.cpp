#include <catch2/catch_test_macros.hpp>

#include "core/PcapNg.h"
#include "PcapNgReader.h"

#include <cstdint>
#include <vector>

using namespace procpcap;

namespace {

// Report the first differing byte, which makes a byte-exact failure readable.
void requireBytesEqual(const std::vector<uint8_t>& got, const std::vector<uint8_t>& want) {
    REQUIRE(got.size() == want.size());
    for (size_t i = 0; i < want.size(); ++i) {
        INFO("first mismatch at byte " << i);
        REQUIRE(static_cast<int>(got[i]) == static_cast<int>(want[i]));
    }
}

} // namespace

TEST_CASE("file header is byte-exact against a hand-built SHB and IDB", "[pcapng]") {
    // appName "procpcap" (8 bytes, no option padding), default snaplen 262144.
    PcapNgWriter writer("procpcap");
    std::vector<uint8_t> got = writer.fileHeader();

    const std::vector<uint8_t> want = {
        // ---- Section Header Block, total length 44 ----
        0x0A, 0x0D, 0x0D, 0x0A,                         // block type
        0x2C, 0x00, 0x00, 0x00,                         // total length = 44
        0x4D, 0x3C, 0x2B, 0x1A,                         // byte-order magic
        0x01, 0x00,                                     // version major 1
        0x00, 0x00,                                     // version minor 0
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // section length: unknown
        0x04, 0x00, 0x08, 0x00,                         // opt shb_userappl, len 8
        'p', 'r', 'o', 'c', 'p', 'c', 'a', 'p',         // "procpcap"
        0x00, 0x00, 0x00, 0x00,                         // opt_endofopt
        0x2C, 0x00, 0x00, 0x00,                         // trailing total length
        // ---- Interface Description Block, total length 32 ----
        0x01, 0x00, 0x00, 0x00,                         // block type
        0x20, 0x00, 0x00, 0x00,                         // total length = 32
        0x65, 0x00,                                     // linktype 101 (RAW)
        0x00, 0x00,                                     // reserved
        0x00, 0x00, 0x04, 0x00,                         // snaplen 262144
        0x09, 0x00, 0x01, 0x00, 0x06, 0x00, 0x00, 0x00, // opt if_tsresol = 6, padded
        0x00, 0x00, 0x00, 0x00,                         // opt_endofopt
        0x20, 0x00, 0x00, 0x00,                         // trailing total length
    };
    requireBytesEqual(got, want);
}

TEST_CASE("packet block is byte-exact against a hand-built EPB", "[pcapng]") {
    PcapNgWriter writer("procpcap");
    const uint8_t packet[2] = {0x45, 0x00};
    // ts = 0x0000000100000002 microseconds: high word 1, low word 2.
    std::vector<uint8_t> got = writer.packetBlock(packet, sizeof(packet), 0x0000000100000002ULL, "hi", 0);

    const std::vector<uint8_t> want = {
        0x06, 0x00, 0x00, 0x00, // block type EPB
        0x30, 0x00, 0x00, 0x00, // total length = 48
        0x00, 0x00, 0x00, 0x00, // interface id 0
        0x01, 0x00, 0x00, 0x00, // timestamp high
        0x02, 0x00, 0x00, 0x00, // timestamp low
        0x02, 0x00, 0x00, 0x00, // captured length 2
        0x02, 0x00, 0x00, 0x00, // original length 2
        0x45, 0x00, 0x00, 0x00, // packet data + 2 pad bytes
        0x01, 0x00, 0x02, 0x00, // opt_comment, len 2
        'h', 'i', 0x00, 0x00,   // "hi" + 2 pad bytes
        0x00, 0x00, 0x00, 0x00, // opt_endofopt
        0x30, 0x00, 0x00, 0x00, // trailing total length
    };
    requireBytesEqual(got, want);
}

TEST_CASE("every block length is a multiple of four", "[pcapng]") {
    PcapNgWriter writer("procpcap 1.0.0");
    auto header = writer.fileHeader();
    REQUIRE(header.size() % 4 == 0);
    // A one-byte payload and an odd-length comment both force padding.
    const uint8_t one[1] = {0x60};
    auto block = writer.packetBlock(one, 1, 123456, "pid 5 odd.exe", 0);
    REQUIRE(block.size() % 4 == 0);
}

TEST_CASE("a written file parses back to the packets and comments put in", "[pcapng]") {
    PcapNgWriter writer("procpcap 1.0.0");
    std::vector<uint8_t> file = writer.fileHeader();

    const uint8_t p0[4] = {0x45, 0x11, 0x22, 0x33};
    const uint8_t p1[3] = {0x60, 0x01, 0x02};
    auto b0 = writer.packetBlock(p0, sizeof(p0), 1000, "pid 100 a.exe", 0);
    auto b1 = writer.packetBlock(p1, sizeof(p1), 2000, "pid 200 b.exe", 0);
    file.insert(file.end(), b0.begin(), b0.end());
    file.insert(file.end(), b1.begin(), b1.end());

    auto r = procpcap_test::readPcapng(file);
    REQUIRE(r.ok);
    REQUIRE(r.linkType == kLinkTypeRaw);
    REQUIRE(r.snapLen == kDefaultSnapLen);
    REQUIRE(r.appName == "procpcap 1.0.0");
    REQUIRE(r.packets.size() == 2);

    REQUIRE(r.packets[0].tsMicros == 1000);
    REQUIRE(r.packets[0].comment == "pid 100 a.exe");
    REQUIRE(r.packets[0].data == std::vector<uint8_t>(p0, p0 + sizeof(p0)));

    REQUIRE(r.packets[1].tsMicros == 2000);
    REQUIRE(r.packets[1].comment == "pid 200 b.exe");
    REQUIRE(r.packets[1].data == std::vector<uint8_t>(p1, p1 + sizeof(p1)));
}

TEST_CASE("an empty comment omits the option but stays well-formed", "[pcapng]") {
    PcapNgWriter writer("x");
    const uint8_t p[4] = {0x45, 0, 0, 0};
    auto block = writer.packetBlock(p, sizeof(p), 42, "", 0);
    std::vector<uint8_t> file = writer.fileHeader();
    file.insert(file.end(), block.begin(), block.end());
    auto r = procpcap_test::readPcapng(file);
    REQUIRE(r.ok);
    REQUIRE(r.packets.size() == 1);
    REQUIRE(r.packets[0].comment.empty());
}
