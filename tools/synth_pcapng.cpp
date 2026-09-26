// synth_pcapng: write a small, deterministic pcapng from a hand-built packet
// list, then read it back and print a summary. It exercises the pcapng writer
// with no driver and no Administrator, which is how the file shown in the README
// is produced. It is a development aid and is not shipped in the release zip.

#include "core/IpPacket.h"
#include "core/PcapNg.h"
#include "PcapNgReader.h"

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

using namespace procpcap;

namespace {

void put16(std::vector<uint8_t>& p, uint16_t v) {
    p.push_back(static_cast<uint8_t>(v >> 8));
    p.push_back(static_cast<uint8_t>(v & 0xFF));
}

// A bare IPv4 packet carrying a UDP or TCP segment with the given payload.
std::vector<uint8_t> ipv4(uint8_t proto, const uint8_t src[4], const uint8_t dst[4], uint16_t sport, uint16_t dport,
                          const std::vector<uint8_t>& payload) {
    std::vector<uint8_t> p;
    const bool tcp = proto == kProtoTcp;
    const size_t transport = tcp ? 20 : 8;
    const size_t total = 20 + transport + payload.size();
    p.resize(20, 0);
    p[0] = 0x45;
    p[1] = 0x00;
    put16(p, static_cast<uint16_t>(total));
    p[4] = 0x00;
    p[5] = 0x00; // id
    p[8] = 64;   // TTL
    p[9] = proto;
    for (int i = 0; i < 4; ++i) {
        p[12 + i] = src[i];
        p[16 + i] = dst[i];
    }
    // transport header
    std::vector<uint8_t> th(transport, 0);
    th[0] = static_cast<uint8_t>(sport >> 8);
    th[1] = static_cast<uint8_t>(sport & 0xFF);
    th[2] = static_cast<uint8_t>(dport >> 8);
    th[3] = static_cast<uint8_t>(dport & 0xFF);
    if (tcp)
        th[12] = 0x50; // data offset 5 words
    p.insert(p.end(), th.begin(), th.end());
    p.insert(p.end(), payload.begin(), payload.end());
    return p;
}

struct Synthetic {
    std::vector<uint8_t> bytes;
    uint64_t tsMicros;
    bool outbound;
    std::string comment;
};

} // namespace

int main(int argc, char** argv) {
    const std::string outPath = argc > 1 ? argv[1] : "synthetic.pcapng";

    const uint8_t local[4] = {192, 168, 1, 20};
    const uint8_t dns[4] = {8, 8, 8, 8};
    const uint8_t web[4] = {93, 184, 216, 34};

    std::vector<Synthetic> packets;
    // Outbound DNS query, low-entropy text payload.
    packets.push_back({ipv4(kProtoUdp, local, dns, 51000, 53, {'g', 'a', 'm', 'e', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'}), 1'000'000,
                       true, "pid 4242 game.exe"});
    // Inbound DNS response.
    packets.push_back({ipv4(kProtoUdp, dns, local, 53, 51000, {0x01, 0x02, 0x03, 0x04}), 1'020'000, false, "pid 4242 game.exe"});
    // Outbound TCP to a web server, high-entropy (looks encrypted) payload.
    packets.push_back(
        {ipv4(kProtoTcp, local, web, 52000, 443, {0x9F, 0x3C, 0xA1, 0x77, 0xE2, 0x08, 0x55, 0xBD}), 1'500'000, true, "pid 4242 game.exe"});

    PcapNgWriter writer("procpcap 1.0.0 (synthetic)");
    std::vector<uint8_t> file = writer.fileHeader();
    for (const auto& s : packets) {
        auto block = writer.packetBlock(s.bytes.data(), s.bytes.size(), s.tsMicros, s.comment);
        file.insert(file.end(), block.begin(), block.end());
    }

    FILE* f = std::fopen(outPath.c_str(), "wb");
    if (f == nullptr) {
        std::fprintf(stderr, "cannot open %s for writing\n", outPath.c_str());
        return 1;
    }
    std::fwrite(file.data(), 1, file.size(), f);
    std::fclose(f);

    // Read it back and print what it holds, so the file is proven, not asserted.
    auto r = procpcap_test::readPcapng(file);
    if (!r.ok) {
        std::fprintf(stderr, "the written file did not parse: %s\n", r.error.c_str());
        return 1;
    }
    std::printf("wrote %s (%zu bytes)\n", outPath.c_str(), file.size());
    std::printf("  application: %s\n", r.appName.c_str());
    std::printf("  link type:   %u (LINKTYPE_RAW)\n", r.linkType);
    std::printf("  packets:     %zu\n", r.packets.size());
    for (size_t i = 0; i < r.packets.size(); ++i) {
        const auto& p = r.packets[i];
        std::printf("    [%zu] ts=%llu us  %zu bytes  comment=\"%s\"\n", i, static_cast<unsigned long long>(p.tsMicros), p.data.size(),
                    p.comment.c_str());
    }
    return 0;
}
