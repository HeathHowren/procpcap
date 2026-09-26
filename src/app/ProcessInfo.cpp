#include "app/ProcessInfo.h"

#include <chrono>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <tlhelp32.h>

namespace procpcap {

namespace {

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

// One Toolhelp snapshot as a table of pid -> (parent pid, image name).
ProcessTable snapshotProcesses() {
    ProcessTable table;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return table;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snap, &entry)) {
        do {
            ProcessEntry& e = table[entry.th32ProcessID];
            e.parentPid = entry.th32ParentProcessID;
            e.imageName = narrow(entry.szExeFile);
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return table;
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
    ProcessTable table = snapshotProcesses();
    auto it = table.find(pid);
    return it == table.end() ? std::string() : it->second.imageName;
}

ProcessResolver::ProcessResolver()
    : selector_([this] {
          // Every snapshot also refreshes the name cache, so a pid that a new
          // process has reused is labeled with the new name.
          ProcessTable table = snapshotProcesses();
          for (const auto& item : table)
              nameCache_[item.first] = item.second.imageName;
          return table;
      }) {}

void ProcessResolver::resolveTargets(const CliOptions& opts) {
    selector_.resolve(opts, std::chrono::steady_clock::now());
}

bool ProcessResolver::isTarget(uint32_t pid) {
    return selector_.isTarget(pid, std::chrono::steady_clock::now());
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
