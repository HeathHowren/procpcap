#include "app/FlowSeed.h"

#include <vector>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>

namespace procpcap {

namespace {

// dwLocalAddr and friends are already in network byte order, which is the wire
// order the packet parser stores, so the four bytes copy straight across.
Endpoint v4Endpoint(DWORD netAddr, DWORD netPort) {
    Endpoint e;
    const uint8_t* b = reinterpret_cast<const uint8_t*>(&netAddr);
    for (int i = 0; i < 4; ++i)
        e.addr[static_cast<size_t>(i)] = b[i];
    e.port = ntohs(static_cast<uint16_t>(netPort & 0xFFFF));
    return e;
}

Endpoint v6Endpoint(const UCHAR addr[16], DWORD netPort) {
    Endpoint e;
    for (int i = 0; i < 16; ++i)
        e.addr[static_cast<size_t>(i)] = addr[i];
    e.port = ntohs(static_cast<uint16_t>(netPort & 0xFFFF));
    return e;
}

template <typename Fn> void withTable(DWORD family, int tableClassTcp, bool udp, Fn&& emit) {
    // Grow the buffer until GetExtended*Table stops asking for more room.
    ULONG size = 0;
    DWORD ret = udp ? GetExtendedUdpTable(nullptr, &size, FALSE, family, static_cast<UDP_TABLE_CLASS>(UDP_TABLE_OWNER_PID), 0)
                    : GetExtendedTcpTable(nullptr, &size, FALSE, family, static_cast<TCP_TABLE_CLASS>(tableClassTcp), 0);
    if (ret != ERROR_INSUFFICIENT_BUFFER || size == 0)
        return;
    std::vector<uint8_t> buf(size);
    ret = udp ? GetExtendedUdpTable(buf.data(), &size, FALSE, family, static_cast<UDP_TABLE_CLASS>(UDP_TABLE_OWNER_PID), 0)
              : GetExtendedTcpTable(buf.data(), &size, FALSE, family, static_cast<TCP_TABLE_CLASS>(tableClassTcp), 0);
    if (ret != NO_ERROR)
        return;
    emit(buf.data());
}

} // namespace

size_t seedFlowTable(FlowTable& table, ProcessResolver& resolver) {
    size_t seeded = 0;

    auto addSeed = [&](const FiveTuple& t, uint32_t pid) {
        if (!resolver.isTarget(pid))
            return; // only seed flows we would actually capture
        FlowRecord rec;
        rec.pid = pid;
        rec.processName = resolver.name(pid);
        rec.startTime = 0;
        table.seed(t, rec);
        ++seeded;
    };

    // TCP, IPv4.
    withTable(AF_INET, TCP_TABLE_OWNER_PID_ALL, false, [&](const uint8_t* p) {
        auto* tbl = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(p);
        for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
            const auto& row = tbl->table[i];
            FiveTuple t;
            t.v6 = false;
            t.protocol = kProtoTcp;
            t.local = v4Endpoint(row.dwLocalAddr, row.dwLocalPort);
            t.remote = v4Endpoint(row.dwRemoteAddr, row.dwRemotePort);
            addSeed(t, row.dwOwningPid);
        }
    });

    // TCP, IPv6.
    withTable(AF_INET6, TCP_TABLE_OWNER_PID_ALL, false, [&](const uint8_t* p) {
        auto* tbl = reinterpret_cast<const MIB_TCP6TABLE_OWNER_PID*>(p);
        for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
            const auto& row = tbl->table[i];
            FiveTuple t;
            t.v6 = true;
            t.protocol = kProtoTcp;
            t.local = v6Endpoint(row.ucLocalAddr, row.dwLocalPort);
            t.remote = v6Endpoint(row.ucRemoteAddr, row.dwRemotePort);
            addSeed(t, row.dwOwningPid);
        }
    });

    // UDP, IPv4. No remote in the table, so only the local end is known.
    withTable(AF_INET, 0, true, [&](const uint8_t* p) {
        auto* tbl = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(p);
        for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
            const auto& row = tbl->table[i];
            FiveTuple t;
            t.v6 = false;
            t.protocol = kProtoUdp;
            t.local = v4Endpoint(row.dwLocalAddr, row.dwLocalPort);
            addSeed(t, row.dwOwningPid);
        }
    });

    // UDP, IPv6.
    withTable(AF_INET6, 0, true, [&](const uint8_t* p) {
        auto* tbl = reinterpret_cast<const MIB_UDP6TABLE_OWNER_PID*>(p);
        for (DWORD i = 0; i < tbl->dwNumEntries; ++i) {
            const auto& row = tbl->table[i];
            FiveTuple t;
            t.v6 = true;
            t.protocol = kProtoUdp;
            t.local = v6Endpoint(row.ucLocalAddr, row.dwLocalPort);
            addSeed(t, row.dwOwningPid);
        }
    });

    return seeded;
}

} // namespace procpcap
