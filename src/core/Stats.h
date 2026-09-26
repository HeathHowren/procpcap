#ifndef PROCPCAP_STATS_H
#define PROCPCAP_STATS_H

#include "core/FlowTable.h"

#include <array>
#include <cstdint>
#include <set>

namespace procpcap {

// A snapshot of the live stats line: rates over the last interval plus running
// totals.
struct StatsSnapshot {
    double packetsPerSec = 0.0;
    double bytesPerSec = 0.0;
    uint64_t totalPackets = 0;
    uint64_t totalBytes = 0;
    size_t distinctEndpoints = 0;
    double meanEntropy = 0.0;
};

// Accumulates capture statistics. Kept free of any timing or I/O so it can be
// unit tested: the caller supplies the elapsed time when it wants a snapshot.
class Stats {
public:
    // Count one captured packet. blockBytes is the packet's size on the wire,
    // remote is the far endpoint (for the distinct-endpoint count), and
    // payloadEntropy is the Shannon entropy of its transport payload.
    void record(uint64_t wireBytes, const Endpoint& remote, double payloadEntropy);

    // Rates over the interval that elapsed since the previous snapshot, then the
    // interval counters reset. elapsedSeconds <= 0 yields zero rates.
    StatsSnapshot snapshot(double elapsedSeconds);

    uint64_t totalPackets() const { return totalPackets_; }
    uint64_t totalBytes() const { return totalBytes_; }
    size_t distinctEndpoints() const { return endpoints_.size(); }
    double meanEntropy() const { return entropyCount_ ? entropySum_ / static_cast<double>(entropyCount_) : 0.0; }

private:
    uint64_t totalPackets_ = 0;
    uint64_t totalBytes_ = 0;
    uint64_t intervalPackets_ = 0;
    uint64_t intervalBytes_ = 0;
    double entropySum_ = 0.0;
    uint64_t entropyCount_ = 0;
    std::set<std::array<uint8_t, 18>> endpoints_; // 16 addr bytes + 2 port bytes
};

} // namespace procpcap

#endif // PROCPCAP_STATS_H
