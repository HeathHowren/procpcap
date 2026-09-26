#ifndef PROCPCAP_TARGETSELECTOR_H
#define PROCPCAP_TARGETSELECTOR_H

#include "core/Cli.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace procpcap {

// One running process as the selector sees it.
struct ProcessEntry {
    uint32_t parentPid = 0;
    std::string imageName; // base name, e.g. "game.exe"
};

// Every running process, keyed by pid.
using ProcessTable = std::unordered_map<uint32_t, ProcessEntry>;

// Returns a fresh process table. The app backs this with a Toolhelp snapshot;
// the tests pass a table they control. This keeps the rules free of Win32.
using ProcessSnapshotFn = std::function<ProcessTable()>;

// Decides which pids to capture.
//
// A pid is a target when:
//   - it was given with --pid, or
//   - its image name contains --name (case insensitive), or
//   - with --children, one of its ancestors is a target or has an image name
//     that contains --name.
// This applies to processes that start after the capture begins, not just the
// ones running at startup.
//
// A "target" answer is kept for the rest of the run. A "not a target" answer is
// kept for kRecheckAfter only. Windows reuses pids, so a new process with a
// matching name can take a pid that did not match earlier; the expiry lets it
// be picked up. Each check takes one snapshot and records an answer for every
// process in it, so busy processes that are not targets cost at most one
// snapshot per kRecheckAfter between them.
class TargetSelector {
public:
    using Clock = std::chrono::steady_clock;

    // How long a "not a target" answer is trusted before it is checked again.
    static constexpr std::chrono::milliseconds kRecheckAfter{250};

    explicit TargetSelector(ProcessSnapshotFn snapshot);

    // Build the initial target set from the command line. With --name or
    // --children this takes one snapshot; with only --pid it takes none.
    void resolve(const CliOptions& opts, Clock::time_point now);

    // Whether a pid should be captured. The capture calls this once per flow
    // event, never per packet. With only --pid given, the answer comes from the
    // fixed set and no snapshot is taken.
    bool isTarget(uint32_t pid, Clock::time_point now);

    // The count of pids known to be targets (for the startup message).
    size_t targetCount() const { return targets_.size(); }

private:
    bool matchesName(const std::string& image) const;
    bool decide(uint32_t pid, const ProcessTable& table) const;
    void absorb(const ProcessTable& table, Clock::time_point now);

    ProcessSnapshotFn snapshot_;
    std::string nameLower_; // --name in lower case; empty if unset
    bool children_ = false;
    std::unordered_set<uint32_t> targets_;
    std::unordered_map<uint32_t, Clock::time_point> notTargets_; // pid -> when it last did not match
};

} // namespace procpcap

#endif // PROCPCAP_TARGETSELECTOR_H
