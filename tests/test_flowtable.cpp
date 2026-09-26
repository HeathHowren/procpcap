#include <catch2/catch_test_macros.hpp>

#include "core/FlowTable.h"

using namespace procpcap;

namespace {

Endpoint v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port) {
    Endpoint e;
    e.addr[0] = a;
    e.addr[1] = b;
    e.addr[2] = c;
    e.addr[3] = d;
    e.port = port;
    return e;
}

FiveTuple tcp(Endpoint local, Endpoint remote) {
    FiveTuple t;
    t.v6 = false;
    t.protocol = kProtoTcp;
    t.local = local;
    t.remote = remote;
    return t;
}

FiveTuple udp(Endpoint local, Endpoint remote) {
    FiveTuple t = tcp(local, remote);
    t.protocol = kProtoUdp;
    return t;
}

FlowRecord rec(uint32_t pid, const char* name, int64_t start) {
    FlowRecord r;
    r.pid = pid;
    r.processName = name;
    r.startTime = start;
    return r;
}

} // namespace

TEST_CASE("establish then lookup returns the owning process", "[flowtable]") {
    FlowTable t;
    FiveTuple flow = tcp(v4(192, 168, 0, 2, 50000), v4(93, 184, 216, 34, 443));
    t.establish(flow, rec(1234, "game.exe", 100));

    const FlowRecord* r = t.lookup(flow);
    REQUIRE(r != nullptr);
    REQUIRE(r->pid == 1234);
    REQUIRE(r->processName == "game.exe");
}

TEST_CASE("an unknown tuple returns nullptr", "[flowtable]") {
    FlowTable t;
    REQUIRE(t.lookup(tcp(v4(10, 0, 0, 1, 1), v4(10, 0, 0, 2, 2))) == nullptr);
}

TEST_CASE("a UDP seed knows only the local port and still matches", "[flowtable]") {
    FlowTable t;
    // Seed carries the local end only (remote left zero), as GetExtendedUdpTable
    // gives it.
    FiveTuple seed = udp(v4(0, 0, 0, 0, 27015), v4(0, 0, 0, 0, 0));
    t.seed(seed, rec(42, "server.exe", 0));

    // A real packet has a full tuple; the exact match misses, the local-port
    // fallback hits.
    FiveTuple packetTuple = udp(v4(192, 168, 0, 2, 27015), v4(8, 8, 8, 8, 53));
    const FlowRecord* r = t.lookup(packetTuple);
    REQUIRE(r != nullptr);
    REQUIRE(r->pid == 42);
    REQUIRE(r->seeded);
}

TEST_CASE("a live record is not overwritten by a later seed", "[flowtable]") {
    FlowTable t;
    FiveTuple flow = tcp(v4(192, 168, 0, 2, 50000), v4(1, 1, 1, 1, 443));
    t.establish(flow, rec(1000, "live.exe", 100));
    t.seed(flow, rec(2000, "seed.exe", 0));

    const FlowRecord* r = t.lookup(flow);
    REQUIRE(r != nullptr);
    REQUIRE(r->processName == "live.exe");
    REQUIRE_FALSE(r->seeded);
}

TEST_CASE("a delete with the wrong start time does not remove a reused flow", "[flowtable]") {
    FlowTable t;
    FiveTuple flow = tcp(v4(192, 168, 0, 2, 50000), v4(1, 1, 1, 1, 443));

    // Process A owns the flow, starting at t=100.
    t.establish(flow, rec(1000, "a.exe", 100));

    // A FLOW_DELETED for a different start time (a stale event) must not erase it.
    t.erase(flow, 999);
    REQUIRE(t.lookup(flow) != nullptr);
    REQUIRE(t.lookup(flow)->processName == "a.exe");

    // The same 5-tuple is reused by a process that also happens to be pid 1000
    // after the first exited, starting at t=200. The name captured at establish
    // time is what a lookup returns, so a later pid reuse cannot mis-attribute.
    t.establish(flow, rec(1000, "b.exe", 200));
    REQUIRE(t.lookup(flow)->processName == "b.exe");

    // A delete matching the current start time removes it; the stale one for the
    // old instance would not have.
    t.erase(flow, 100);
    REQUIRE(t.lookup(flow) != nullptr); // 100 no longer current, so kept
    t.erase(flow, 200);
    REQUIRE(t.lookup(flow) == nullptr);
}

TEST_CASE("size counts distinct tuples", "[flowtable]") {
    FlowTable t;
    t.establish(tcp(v4(10, 0, 0, 1, 1000), v4(1, 1, 1, 1, 80)), rec(1, "a", 1));
    t.establish(tcp(v4(10, 0, 0, 1, 1001), v4(1, 1, 1, 1, 80)), rec(1, "a", 2));
    REQUIRE(t.size() == 2);
}
