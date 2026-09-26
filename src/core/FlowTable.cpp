#include "core/FlowTable.h"

#include <functional>
#include <utility>

namespace procpcap {

size_t FiveTupleHash::operator()(const FiveTuple& t) const noexcept {
    // FNV-1a over the identifying fields. Not cryptographic; just a spread for
    // the hash map.
    uint64_t h = 1469598103934665603ULL;
    auto mix = [&h](uint8_t b) {
        h ^= b;
        h *= 1099511628211ULL;
    };
    mix(t.v6 ? 1 : 0);
    mix(t.protocol);
    for (uint8_t b : t.local.addr)
        mix(b);
    for (uint8_t b : t.remote.addr)
        mix(b);
    mix(static_cast<uint8_t>(t.local.port & 0xFF));
    mix(static_cast<uint8_t>(t.local.port >> 8));
    mix(static_cast<uint8_t>(t.remote.port & 0xFF));
    mix(static_cast<uint8_t>(t.remote.port >> 8));
    return static_cast<size_t>(h);
}

void FlowTable::establish(const FiveTuple& t, FlowRecord rec) {
    if (t.protocol == kProtoUdp)
        udpByLocalPort_[udpKey(t.v6, t.local.port)] = rec;
    exact_[t] = std::move(rec);
}

void FlowTable::seed(const FiveTuple& t, FlowRecord rec) {
    rec.seeded = true;
    if (t.protocol == kProtoUdp) {
        auto key = udpKey(t.v6, t.local.port);
        auto it = udpByLocalPort_.find(key);
        if (it == udpByLocalPort_.end() || it->second.seeded)
            udpByLocalPort_[key] = rec;
    }
    auto it = exact_.find(t);
    if (it != exact_.end() && !it->second.seeded)
        return; // keep the live record
    exact_[t] = std::move(rec);
}

void FlowTable::erase(const FiveTuple& t, int64_t startTime) {
    auto it = exact_.find(t);
    if (it != exact_.end() && it->second.startTime == startTime) {
        if (t.protocol == kProtoUdp) {
            auto uit = udpByLocalPort_.find(udpKey(t.v6, t.local.port));
            if (uit != udpByLocalPort_.end() && uit->second.startTime == startTime)
                udpByLocalPort_.erase(uit);
        }
        exact_.erase(it);
    }
}

const FlowRecord* FlowTable::lookup(const FiveTuple& t) const {
    auto it = exact_.find(t);
    if (it != exact_.end())
        return &it->second;
    if (t.protocol == kProtoUdp) {
        auto uit = udpByLocalPort_.find(udpKey(t.v6, t.local.port));
        if (uit != udpByLocalPort_.end())
            return &uit->second;
    }
    return nullptr;
}

} // namespace procpcap
