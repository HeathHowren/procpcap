#include "app/ProcessInfo.h"

#include <algorithm>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>

namespace procpcap {

namespace {

std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string narrow(const wchar_t* w) {
    if (w == nullptr || w[0] == 0)
        return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 1)
        return {};
    std::string out(static_cast<size_t>(len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), len, nullptr, nullptr);
    return out;
}

std::string baseName(const std::string& path) {
    size_t slash = path.find_last_of("\\/");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

} // namespace

std::string imageNameForPid(uint32_t pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (h != nullptr) {
        wchar_t buf[MAX_PATH];
        DWORD size = MAX_PATH;
        std::string result;
        if (QueryFullProcessImageNameW(h, 0, buf, &size))
            result = baseName(narrow(buf));
        CloseHandle(h);
        if (!result.empty())
            return result;
    }
    // Fall back to the snapshot, which reports names for processes that cannot be
    // opened for a query.
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return {};
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    std::string result;
    if (Process32FirstW(snap, &entry)) {
        do {
            if (entry.th32ProcessID == pid) {
                result = narrow(entry.szExeFile);
                break;
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return result;
}

bool ProcessResolver::matchesName(const std::string& image) const {
    if (opts_.nameSubstr.empty())
        return false;
    return toLower(image).find(toLower(opts_.nameSubstr)) != std::string::npos;
}

void ProcessResolver::resolveTargets(const CliOptions& opts) {
    opts_ = opts;
    targets_.clear();
    for (uint32_t pid : opts.pids)
        targets_.insert(pid);

    // One snapshot supplies both the name matches and the parent links.
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return;

    std::vector<std::pair<uint32_t, uint32_t>> parents; // (pid, ppid)
    std::vector<std::pair<uint32_t, std::string>> names;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
        do {
            uint32_t pid = entry.th32ProcessID;
            uint32_t ppid = entry.th32ParentProcessID;
            std::string image = narrow(entry.szExeFile);
            parents.emplace_back(pid, ppid);
            names.emplace_back(pid, image);
            nameCache_[pid] = image;
            if (matchesName(image))
                targets_.insert(pid);
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);

    if (opts.children) {
        // Expand the set to every descendant of a target. Iterate to a fixed
        // point so grandchildren are caught too.
        bool grew = true;
        while (grew) {
            grew = false;
            for (auto& [pid, ppid] : parents) {
                if (targets_.count(pid) == 0 && targets_.count(ppid) != 0) {
                    targets_.insert(pid);
                    grew = true;
                }
            }
        }
    }
}

bool ProcessResolver::isTarget(uint32_t pid) {
    if (pid == 0)
        return false;
    if (targets_.count(pid) != 0)
        return true;
    if (!opts_.children)
        return false;

    // Walk the parent chain for a process that appeared after startup. Guard
    // against loops and a runaway chain.
    uint32_t current = pid;
    for (int guard = 0; guard < 64 && current != 0; ++guard) {
        uint32_t parent = 0;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
            return false;
        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        bool found = false;
        if (Process32FirstW(snap, &entry)) {
            do {
                if (entry.th32ProcessID == current) {
                    parent = entry.th32ParentProcessID;
                    found = true;
                    break;
                }
            } while (Process32NextW(snap, &entry));
        }
        CloseHandle(snap);
        if (!found)
            return false;
        if (targets_.count(parent) != 0) {
            targets_.insert(pid); // memoise so we do not walk again
            return true;
        }
        current = parent;
    }
    return false;
}

std::string ProcessResolver::name(uint32_t pid) {
    auto it = nameCache_.find(pid);
    if (it != nameCache_.end() && !it->second.empty())
        return it->second;
    std::string image = imageNameForPid(pid);
    if (image.empty())
        image = "pid " + std::to_string(pid);
    nameCache_[pid] = image;
    return image;
}

} // namespace procpcap
