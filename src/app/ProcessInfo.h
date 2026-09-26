#ifndef PROCPCAP_PROCESSINFO_H
#define PROCPCAP_PROCESSINFO_H

#include "core/Cli.h"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace procpcap {

// Resolves which process ids to capture and gives each a display name. Wraps the
// Toolhelp snapshot and the process-image query, so the capture loop deals only
// in pids and names.
class ProcessResolver {
public:
    // Build the initial target set from the command line: the explicit --pid
    // values, plus every process whose image name contains --name (case
    // insensitive), plus their descendants when --children is set.
    void resolveTargets(const CliOptions& opts);

    // Whether a pid should be captured. With --children this also walks the
    // parent chain, so a child spawned after startup is still matched.
    bool isTarget(uint32_t pid);

    // The image name for a pid, e.g. "game.exe". Cached; falls back to
    // "pid <n>" if the process is gone or cannot be opened.
    std::string name(uint32_t pid);

    // The count of pids in the initial target set (for the startup message).
    size_t initialTargetCount() const { return targets_.size(); }

private:
    bool matchesName(const std::string& image) const;

    CliOptions opts_;
    std::unordered_set<uint32_t> targets_;
    std::unordered_map<uint32_t, std::string> nameCache_;
};

// The image base name for a pid, or an empty string. Free function so tests and
// seeding code can use it without a resolver.
std::string imageNameForPid(uint32_t pid);

} // namespace procpcap

#endif // PROCPCAP_PROCESSINFO_H
