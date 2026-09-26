#ifndef PROCPCAP_PROCESSINFO_H
#define PROCPCAP_PROCESSINFO_H

#include "core/Cli.h"
#include "core/TargetSelector.h"

#include <cstdint>
#include <string>
#include <unordered_map>

namespace procpcap {

// Resolves which process ids to capture and gives each a display name. Feeds
// Toolhelp snapshots to a TargetSelector, which holds the rules, so the capture
// loop deals only in pids and names.
class ProcessResolver {
public:
    ProcessResolver();

    // The snapshot callback points back at this object, so it cannot be copied.
    ProcessResolver(const ProcessResolver&) = delete;
    ProcessResolver& operator=(const ProcessResolver&) = delete;

    // Build the initial target set from the command line: the explicit --pid
    // values, plus every running process whose image name contains --name (case
    // insensitive), plus their descendants when --children is set.
    void resolveTargets(const CliOptions& opts);

    // Whether a pid should be captured. Called once per flow event, not per
    // packet. A process that starts after startup is a target if its image name
    // contains --name or, with --children, if an ancestor is a target or has a
    // matching name. A pid that did not match is checked again after a short
    // time, since Windows reuses pids. See TargetSelector for the details.
    bool isTarget(uint32_t pid);

    // The image name for a pid, e.g. "game.exe". Cached, and refreshed from
    // every snapshot so a reused pid gets the new process's name. Falls back to
    // "pid <n>" if the process is gone or cannot be opened.
    std::string name(uint32_t pid);

    // The count of target pids. Called right after resolveTargets, for the
    // startup message.
    size_t initialTargetCount() const { return selector_.targetCount(); }

private:
    TargetSelector selector_;
    std::unordered_map<uint32_t, std::string> nameCache_;
};

// The image base name for a pid, or an empty string. Free function so tests and
// seeding code can use it without a resolver.
std::string imageNameForPid(uint32_t pid);

} // namespace procpcap

#endif // PROCPCAP_PROCESSINFO_H
