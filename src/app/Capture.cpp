#include "app/Capture.h"

#include "app/FlowSeed.h"
#include "app/ProcessInfo.h"
#include "core/Entropy.h"
#include "core/FlowTable.h"
#include "core/IpPacket.h"
#include "core/PcapNg.h"
#include "core/Stats.h"

#include "Version.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <fcntl.h>
#include <io.h>

#include "windivert.h"

namespace procpcap {

namespace {

std::atomic<bool> g_stop{false};

BOOL WINAPI consoleHandler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT || signal == CTRL_CLOSE_EVENT) {
        g_stop.store(true);
        return TRUE;
    }
    return FALSE;
}

bool isElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;
    TOKEN_ELEVATION elevation{};
    DWORD size = sizeof(elevation);
    bool elevated = false;
    if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size))
        elevated = elevation.TokenIsElevated != 0;
    CloseHandle(token);
    return elevated;
}

// A binary output target: a file, or stdout for a Wireshark pipe.
class Sink {
public:
    bool openFile(const std::string& utf8Path) {
        std::wstring wide;
        int len = MultiByteToWideChar(CP_UTF8, 0, utf8Path.c_str(), -1, nullptr, 0);
        if (len > 0) {
            wide.resize(static_cast<size_t>(len - 1));
            MultiByteToWideChar(CP_UTF8, 0, utf8Path.c_str(), -1, wide.data(), len);
        }
        file_ = _wfopen(wide.c_str(), L"wb");
        return file_ != nullptr;
    }

    void openStdout() {
        _setmode(_fileno(stdout), _O_BINARY);
        file_ = stdout;
        isStdout_ = true;
    }

    bool write(const std::vector<uint8_t>& bytes) {
        if (bytes.empty())
            return true;
        return fwrite(bytes.data(), 1, bytes.size(), file_) == bytes.size();
    }

    void flush() {
        if (file_ != nullptr)
            fflush(file_);
    }

    ~Sink() {
        if (file_ != nullptr && !isStdout_)
            fclose(file_);
    }

private:
    FILE* file_ = nullptr;
    bool isStdout_ = false;
};

// Convert a WinDivert FLOW-layer address into a core 5-tuple. FLOW addresses are
// IPv4-mapped IPv6; the address header's IPv6 bit says which family the flow is.
FiveTuple flowTuple(const WINDIVERT_ADDRESS& addr) {
    const WINDIVERT_DATA_FLOW& f = addr.Flow;
    FiveTuple t;
    t.v6 = addr.IPv6 != 0;
    t.protocol = f.Protocol;

    UINT32 localNet[4];
    UINT32 remoteNet[4];
    WinDivertHelperNtohIPv6Address(f.LocalAddr, localNet);
    WinDivertHelperNtohIPv6Address(f.RemoteAddr, remoteNet);
    const uint8_t* lb = reinterpret_cast<const uint8_t*>(localNet);
    const uint8_t* rb = reinterpret_cast<const uint8_t*>(remoteNet);
    if (t.v6) {
        for (int i = 0; i < 16; ++i) {
            t.local.addr[static_cast<size_t>(i)] = lb[i];
            t.remote.addr[static_cast<size_t>(i)] = rb[i];
        }
    } else {
        // The IPv4 octets are the last four bytes of the mapped address.
        for (int i = 0; i < 4; ++i) {
            t.local.addr[static_cast<size_t>(i)] = lb[12 + i];
            t.remote.addr[static_cast<size_t>(i)] = rb[12 + i];
        }
    }
    t.local.port = f.LocalPort;
    t.remote.port = f.RemotePort;
    return t;
}

// Maps a WinDivert timestamp (a QueryPerformanceCounter value) to microseconds
// since the Unix epoch, using one reference pair captured at startup.
class Clock {
public:
    Clock() {
        LARGE_INTEGER freq;
        QueryPerformanceFrequency(&freq);
        freq_ = static_cast<double>(freq.QuadPart);
        LARGE_INTEGER qpc;
        QueryPerformanceCounter(&qpc);
        baseQpc_ = qpc.QuadPart;

        FILETIME ft;
        GetSystemTimePreciseAsFileTime(&ft);
        uint64_t ft100ns = (static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime;
        // FILETIME is 100 ns ticks since 1601-01-01; shift the epoch to 1970.
        constexpr uint64_t kEpochDelta100ns = 116444736000000000ULL;
        baseEpochMicros_ = (ft100ns - kEpochDelta100ns) / 10ULL;
    }

    uint64_t toEpochMicros(int64_t winDivertTs) const {
        double deltaSec = static_cast<double>(winDivertTs - baseQpc_) / freq_;
        return baseEpochMicros_ + static_cast<uint64_t>(deltaSec * 1e6);
    }

private:
    double freq_ = 1.0;
    int64_t baseQpc_ = 0;
    uint64_t baseEpochMicros_ = 0;
};

std::string mapOpenError(DWORD err) {
    switch (err) {
    case ERROR_ACCESS_DENIED:
        return "access denied. Run procpcap from an Administrator prompt.";
    case ERROR_FILE_NOT_FOUND:
        return "WinDivert.dll or WinDivert64.sys was not found next to procpcap.exe.";
    case ERROR_INVALID_IMAGE_HASH:
        return "the WinDivert driver signature was rejected. Secure Boot with HVCI or "
               "Smart App Control can block it; see the README.";
    case ERROR_SERVICE_DOES_NOT_EXIST:
        return "the WinDivert driver service could not be created.";
    default:
        return "WinDivertOpen failed with error " + std::to_string(err) + ".";
    }
}

// A packet held back because its flow was not known yet. First data packets can
// arrive before the FLOW_ESTABLISHED event that names their process, so an
// unmatched packet waits briefly and is re-checked.
struct PendingPacket {
    std::vector<uint8_t> bytes;
    uint64_t tsMicros = 0;
    bool outbound = false;
    std::chrono::steady_clock::time_point arrived;
};

constexpr auto kPendingWait = std::chrono::milliseconds(100);

} // namespace

void requestStop() { g_stop.store(true); }

int runCapture(const CliOptions& opts) {
    if (!isElevated()) {
        std::fprintf(stderr, "procpcap needs Administrator. Right-click your terminal and Run as administrator.\n");
        return 2;
    }

    ProcessResolver resolver;
    resolver.resolveTargets(opts);
    if (resolver.initialTargetCount() == 0)
        std::fprintf(stderr, "warning: no process matched the selector yet; waiting for one to appear.\n");

    FlowTable flows;
    std::mutex flowsMutex;
    {
        std::lock_guard<std::mutex> lock(flowsMutex);
        size_t seeded = seedFlowTable(flows, resolver);
        std::fprintf(stderr, "seeded %zu existing flow(s) from the connection table.\n", seeded);
    }

    Sink sink;
    if (opts.toStdout) {
        sink.openStdout();
    } else if (!sink.openFile(opts.output)) {
        std::fprintf(stderr, "cannot open output file: %s\n", opts.output.c_str());
        return 2;
    }

    // Open the FLOW handle first so it is listening before packets flow.
    HANDLE flowHandle = WinDivertOpen("true", WINDIVERT_LAYER_FLOW, 0, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    if (flowHandle == INVALID_HANDLE_VALUE) {
        std::fprintf(stderr, "opening the WinDivert FLOW layer failed: %s\n", mapOpenError(GetLastError()).c_str());
        return 3;
    }

    HANDLE netHandle = WinDivertOpen("ip or ipv6", WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    if (netHandle == INVALID_HANDLE_VALUE) {
        std::fprintf(stderr, "opening the WinDivert NETWORK layer failed: %s\n", mapOpenError(GetLastError()).c_str());
        WinDivertClose(flowHandle);
        return 3;
    }

    SetConsoleCtrlHandler(consoleHandler, TRUE);
    Clock clock;

    PcapNgWriter writer("procpcap " PROCPCAP_VERSION_STRING);
    if (!sink.write(writer.fileHeader())) {
        std::fprintf(stderr, "writing the pcapng header failed.\n");
        WinDivertClose(flowHandle);
        WinDivertClose(netHandle);
        return 4;
    }

    Stats stats;
    std::mutex statsMutex;

    // FLOW thread: keep the flow table current as connections open and close.
    std::thread flowThread([&]() {
        WINDIVERT_ADDRESS addr;
        while (!g_stop.load()) {
            UINT recvLen = 0;
            if (!WinDivertRecv(flowHandle, nullptr, 0, &recvLen, &addr)) {
                if (GetLastError() == ERROR_NO_DATA) // handle shut down
                    break;
                continue;
            }
            uint32_t pid = addr.Flow.ProcessId;
            if (!resolver.isTarget(pid))
                continue;
            FiveTuple t = flowTuple(addr);
            std::lock_guard<std::mutex> lock(flowsMutex);
            if (addr.Event == WINDIVERT_EVENT_FLOW_ESTABLISHED) {
                FlowRecord rec;
                rec.pid = pid;
                rec.processName = resolver.name(pid);
                rec.startTime = addr.Timestamp;
                flows.establish(t, rec);
            } else if (addr.Event == WINDIVERT_EVENT_FLOW_DELETED) {
                flows.erase(t, addr.Timestamp);
            }
        }
    });

    // Stats thread: one line per second to stderr.
    std::thread statsThread([&]() {
        auto last = std::chrono::steady_clock::now();
        while (!g_stop.load()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            auto now = std::chrono::steady_clock::now();
            double elapsed = std::chrono::duration<double>(now - last).count();
            last = now;
            StatsSnapshot s;
            {
                std::lock_guard<std::mutex> lock(statsMutex);
                s = stats.snapshot(elapsed);
            }
            std::fprintf(stderr, "\r%8.0f pkt/s  %9.0f B/s  %6zu endpoints  entropy %.2f  (%llu packets)   ",
                         s.packetsPerSec, s.bytesPerSec, s.distinctEndpoints, s.meanEntropy,
                         static_cast<unsigned long long>(s.totalPackets));
            std::fflush(stderr);
        }
    });

    // Capture loop with overlapped receive so it wakes to flush the pending
    // buffer and to notice a stop request even when traffic is quiet.
    std::vector<uint8_t> packet(65536);
    std::deque<PendingPacket> pending;
    OVERLAPPED overlapped{};
    HANDLE event = CreateEventW(nullptr, FALSE, FALSE, nullptr);

    auto writePacket = [&](const uint8_t* data, size_t len, uint64_t tsMicros, bool outbound) -> bool {
        ParsedPacket parsed = parseIp(data, len);
        FiveTuple t = tupleFromPacket(parsed, outbound);
        std::string comment;
        Endpoint remote = t.remote;
        {
            std::lock_guard<std::mutex> lock(flowsMutex);
            const FlowRecord* rec = flows.lookup(t);
            if (rec == nullptr)
                return false; // still unknown
            comment = "pid " + std::to_string(rec->pid) + " " + rec->processName;
        }
        double entropy = parsed.payloadLength > 0 ? shannonEntropy(data + parsed.payloadOffset, parsed.payloadLength) : 0.0;
        {
            std::lock_guard<std::mutex> lock(statsMutex);
            stats.record(len, remote, entropy);
        }
        return sink.write(writer.packetBlock(data, len, tsMicros, comment));
    };

    auto flushPending = [&]() {
        auto now = std::chrono::steady_clock::now();
        for (auto it = pending.begin(); it != pending.end();) {
            if (writePacket(it->bytes.data(), it->bytes.size(), it->tsMicros, it->outbound)) {
                it = pending.erase(it);
            } else if (now - it->arrived >= kPendingWait) {
                it = pending.erase(it); // gave it 100 ms; drop, it is not ours
            } else {
                ++it;
            }
        }
    };

    while (!g_stop.load()) {
        UINT recvLen = 0;
        WINDIVERT_ADDRESS addr;
        ResetEvent(event);
        overlapped = OVERLAPPED{};
        overlapped.hEvent = event;
        UINT addrLen = sizeof(addr);
        if (WinDivertRecvEx(netHandle, packet.data(), static_cast<UINT>(packet.size()), &recvLen, 0, &addr, &addrLen, &overlapped)) {
            // Completed synchronously.
        } else {
            DWORD err = GetLastError();
            if (err == ERROR_NO_DATA)
                break;
            if (err != ERROR_IO_PENDING) {
                flushPending();
                continue;
            }
            DWORD waited = WaitForSingleObject(event, 50);
            if (waited == WAIT_TIMEOUT) {
                CancelIoEx(netHandle, &overlapped);
                WaitForSingleObject(event, INFINITE);
                flushPending();
                continue;
            }
            DWORD transferred = 0;
            if (!GetOverlappedResult(netHandle, &overlapped, &transferred, TRUE)) {
                flushPending();
                continue;
            }
            recvLen = transferred;
        }

        if (recvLen == 0) {
            flushPending();
            continue;
        }

        uint64_t tsMicros = clock.toEpochMicros(addr.Timestamp);
        bool outbound = addr.Outbound != 0;
        if (!writePacket(packet.data(), recvLen, tsMicros, outbound)) {
            PendingPacket p;
            p.bytes.assign(packet.data(), packet.data() + recvLen);
            p.tsMicros = tsMicros;
            p.outbound = outbound;
            p.arrived = std::chrono::steady_clock::now();
            pending.push_back(std::move(p));
        }
        flushPending();
    }

    g_stop.store(true);
    WinDivertShutdown(flowHandle, WINDIVERT_SHUTDOWN_BOTH);
    WinDivertShutdown(netHandle, WINDIVERT_SHUTDOWN_BOTH);
    if (flowThread.joinable())
        flowThread.join();
    if (statsThread.joinable())
        statsThread.join();
    CloseHandle(event);
    WinDivertClose(flowHandle);
    WinDivertClose(netHandle);
    sink.flush();

    std::fprintf(stderr, "\ncapture stopped. %llu packets written.\n", static_cast<unsigned long long>(stats.totalPackets()));
    return 0;
}

} // namespace procpcap
