#ifndef PROCPCAP_FLOWTABLE_H
#define PROCPCAP_FLOWTABLE_H

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

namespace procpcap {

// Protocol numbers as they appear in an IP header.
constexpr uint8_t kProtoTcp = 6;
constexpr uint8_t kProtoUdp = 17;

// One end of a connection. Addresses are stored as raw network-order bytes:
// IPv4 in bytes [0..3] with the rest zero, IPv6 across all sixteen. Ports are
// kept in host order.
struct Endpoint {
    std::array<uint8_t, 16> addr{};
    uint16_t port = 0;

    bool operator==(const Endpoint& o) const { return addr == o.addr && port == o.port; }
};

// A connection identified from the local host's point of view. WinDivert's FLOW
// layer reports local and remote directly; a sniffed packet is turned into this
// form using its outbound flag (see tupleFromPacket).
struct FiveTuple {
    bool v6 = false;
    uint8_t protocol = 0;
    Endpoint local;
    Endpoint remote;

    bool operator==(const FiveTuple& o) const {
        return v6 == o.v6 && protocol == o.protocol && local == o.local && remote == o.remote;
    }
};

struct FiveTupleHash {
    size_t operator()(const FiveTuple& t) const noexcept;
};

// What is known about a flow: the owning process and the moment the flow began.
// startTime is part of the flow's identity, not just data, so that a 5-tuple
// reused by a different process after the first one exits is never confused with
// the original (see FlowTable::erase).
struct FlowRecord {
    uint32_t pid = 0;
    std::string processName;
    int64_t startTime = 0; // WinDivert timestamp of FLOW_ESTABLISHED, or 0 for a seed
    bool seeded = false;   // read from GetExtendedTcp/UdpTable at startup, not a live event
};

// Maps flow 5-tuples to the process that owns them.
//
// The table is keyed on (5-tuple, start time). A lookup only has the 5-tuple, so
// it returns the current record for that tuple; the start time is used on
// deletion, so that a FLOW_DELETED for an old flow cannot remove a newer flow
// that happens to reuse the same 5-tuple.
//
// UDP is connectionless. Seeds from GetExtendedUdpTable carry only the local
// address and port, so UDP lookups fall back to a local-port match when the full
// tuple is not present.
class FlowTable {
public:
    // Record a flow from a FLOW_ESTABLISHED event. Replaces any existing record
    // for the tuple.
    void establish(const FiveTuple& t, FlowRecord rec);

    // Record a flow discovered at startup. Does not overwrite a live (non-seeded)
    // record, since a live event is always more precise than a seed.
    void seed(const FiveTuple& t, FlowRecord rec);

    // Remove a flow from a FLOW_DELETED event. The record is erased only if its
    // stored start time matches, so a reused tuple is left alone.
    void erase(const FiveTuple& t, int64_t startTime);

    // Find the owning process for a captured packet's tuple, or nullptr.
    const FlowRecord* lookup(const FiveTuple& t) const;

    size_t size() const { return exact_.size(); }

private:
    static uint64_t udpKey(bool v6, uint16_t localPort) {
        return (static_cast<uint64_t>(v6 ? 1 : 0) << 16) | localPort;
    }

    std::unordered_map<FiveTuple, FlowRecord, FiveTupleHash> exact_;
    // Fallback index for UDP: (v6, local port) -> record. Populated for every UDP
    // flow so a seeded entry, which knows only the local port, still resolves.
    std::unordered_map<uint64_t, FlowRecord> udpByLocalPort_;
};

} // namespace procpcap

#endif // PROCPCAP_FLOWTABLE_H
