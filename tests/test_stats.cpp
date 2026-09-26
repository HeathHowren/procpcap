#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_floating_point.hpp>

#include "core/Stats.h"

using namespace procpcap;
using Catch::Matchers::WithinAbs;

namespace {
Endpoint ep(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port) {
    Endpoint e;
    e.addr[0] = a;
    e.addr[1] = b;
    e.addr[2] = c;
    e.addr[3] = d;
    e.port = port;
    return e;
}
} // namespace

TEST_CASE("distinct endpoints are counted once each", "[stats]") {
    Stats s;
    s.record(100, ep(8, 8, 8, 8, 53), 0.0);
    s.record(100, ep(8, 8, 8, 8, 53), 0.0); // same endpoint again
    s.record(100, ep(1, 1, 1, 1, 443), 0.0);
    REQUIRE(s.distinctEndpoints() == 2);
    REQUIRE(s.totalPackets() == 3);
    REQUIRE(s.totalBytes() == 300);
}

TEST_CASE("the same address on two ports is two endpoints", "[stats]") {
    Stats s;
    s.record(1, ep(1, 2, 3, 4, 80), 0.0);
    s.record(1, ep(1, 2, 3, 4, 443), 0.0);
    REQUIRE(s.distinctEndpoints() == 2);
}

TEST_CASE("mean entropy averages the per-packet values", "[stats]") {
    Stats s;
    s.record(1, ep(1, 1, 1, 1, 1), 2.0);
    s.record(1, ep(2, 2, 2, 2, 2), 4.0);
    REQUIRE_THAT(s.meanEntropy(), WithinAbs(3.0, 1e-9));
}

TEST_CASE("snapshot computes rates over the interval and resets it", "[stats]") {
    Stats s;
    s.record(1000, ep(1, 1, 1, 1, 1), 0.0);
    s.record(1000, ep(1, 1, 1, 1, 1), 0.0);
    StatsSnapshot first = s.snapshot(2.0); // 2 packets, 2000 bytes over 2 s
    REQUIRE_THAT(first.packetsPerSec, WithinAbs(1.0, 1e-9));
    REQUIRE_THAT(first.bytesPerSec, WithinAbs(1000.0, 1e-9));
    REQUIRE(first.totalPackets == 2);

    // The interval counters reset, so with no new packets the next rate is zero
    // while the totals stand.
    StatsSnapshot second = s.snapshot(1.0);
    REQUIRE_THAT(second.packetsPerSec, WithinAbs(0.0, 1e-9));
    REQUIRE(second.totalPackets == 2);
}

TEST_CASE("a non-positive interval yields zero rates", "[stats]") {
    Stats s;
    s.record(500, ep(1, 1, 1, 1, 1), 0.0);
    StatsSnapshot snap = s.snapshot(0.0);
    REQUIRE(snap.packetsPerSec == 0.0);
    REQUIRE(snap.bytesPerSec == 0.0);
}
