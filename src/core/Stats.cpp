#include "core/Stats.h"

namespace procpcap {

void Stats::record(uint64_t wireBytes, const Endpoint& remote, double payloadEntropy) {
    ++totalPackets_;
    ++intervalPackets_;
    totalBytes_ += wireBytes;
    intervalBytes_ += wireBytes;

    entropySum_ += payloadEntropy;
    ++entropyCount_;

    std::array<uint8_t, 18> key{};
    for (size_t i = 0; i < 16; ++i)
        key[i] = remote.addr[i];
    key[16] = static_cast<uint8_t>(remote.port & 0xFF);
    key[17] = static_cast<uint8_t>((remote.port >> 8) & 0xFF);
    endpoints_.insert(key);
}

StatsSnapshot Stats::snapshot(double elapsedSeconds) {
    StatsSnapshot s;
    s.totalPackets = totalPackets_;
    s.totalBytes = totalBytes_;
    s.distinctEndpoints = endpoints_.size();
    s.meanEntropy = meanEntropy();
    if (elapsedSeconds > 0.0) {
        s.packetsPerSec = static_cast<double>(intervalPackets_) / elapsedSeconds;
        s.bytesPerSec = static_cast<double>(intervalBytes_) / elapsedSeconds;
    }
    intervalPackets_ = 0;
    intervalBytes_ = 0;
    return s;
}

} // namespace procpcap
