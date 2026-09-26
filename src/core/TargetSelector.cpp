#include "core/TargetSelector.h"

#include <algorithm>
#include <cctype>
#include <utility>

namespace procpcap {

namespace {

// Deeper than any real process tree. It also stops a parent-pid loop, which
// Windows can report once a parent's pid has been reused.
constexpr int kMaxDepth = 64;

std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

} // namespace

TargetSelector::TargetSelector(ProcessSnapshotFn snapshot) : snapshot_(std::move(snapshot)) {}

bool TargetSelector::matchesName(const std::string& image) const {
    return !nameLower_.empty() && toLower(image).find(nameLower_) != std::string::npos;
}

bool TargetSelector::decide(uint32_t pid, const ProcessTable& table) const {
    auto it = table.find(pid);
    if (it == table.end())
        return false; // already exited
    if (matchesName(it->second.imageName))
        return true;
    if (!children_)
        return false;

    // Walk up the parent chain. An ancestor counts if it is already a target
    // (a --pid, say) or if its own name matches.
    uint32_t current = pid;
    for (int depth = 0; depth < kMaxDepth; ++depth) {
        uint32_t parent = it->second.parentPid;
        if (parent == 0 || parent == current)
            return false;
        if (targets_.count(parent) != 0)
            return true;
        it = table.find(parent);
        if (it == table.end())
            return false;
        if (matchesName(it->second.imageName))
            return true;
        current = parent;
    }
    return false;
}

void TargetSelector::absorb(const ProcessTable& table, Clock::time_point now) {
    for (const auto& item : table) {
        uint32_t pid = item.first;
        if (pid == 0 || targets_.count(pid) != 0)
            continue;
        if (decide(pid, table)) {
            targets_.insert(pid); // memoize: a target stays a target
            notTargets_.erase(pid);
        } else {
            notTargets_[pid] = now;
        }
    }
}

void TargetSelector::resolve(const CliOptions& opts, Clock::time_point now) {
    nameLower_ = toLower(opts.nameSubstr);
    children_ = opts.children;
    targets_.clear();
    notTargets_.clear();
    for (uint32_t pid : opts.pids)
        targets_.insert(pid);
    if (nameLower_.empty() && !children_)
        return; // --pid alone: the set is fixed

    // One snapshot supplies both the name matches and the parent links.
    absorb(snapshot_(), now);
}

bool TargetSelector::isTarget(uint32_t pid, Clock::time_point now) {
    if (pid == 0)
        return false;
    if (targets_.count(pid) != 0)
        return true;
    if (nameLower_.empty() && !children_)
        return false; // --pid alone: the set is fixed

    auto it = notTargets_.find(pid);
    if (it != notTargets_.end() && now - it->second < kRecheckAfter)
        return false;

    absorb(snapshot_(), now);
    if (targets_.count(pid) != 0)
        return true;
    notTargets_[pid] = now; // covers a pid missing from the snapshot, which has exited
    return false;
}

} // namespace procpcap
