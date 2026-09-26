#include "app/Capture.h"
#include "core/Cli.h"

#include "Version.h"

#include <cstdio>
#include <string>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <shellapi.h>

// Turn the wide argv into UTF-8 so a non-ASCII output path survives.
static std::vector<std::string> collectArgs() {
    std::vector<std::string> args;
    int argc = 0;
    LPWSTR* wargv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (wargv == nullptr)
        return args;
    for (int i = 1; i < argc; ++i) {
        int len = WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, nullptr, 0, nullptr, nullptr);
        std::string a(len > 0 ? static_cast<size_t>(len - 1) : 0, '\0');
        if (len > 0)
            WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, a.data(), len, nullptr, nullptr);
        args.push_back(std::move(a));
    }
    LocalFree(wargv);
    return args;
}

int main() {
    std::vector<std::string> args = collectArgs();
    procpcap::CliResult parsed = procpcap::parseCli(args);

    if (parsed.opts.showHelp) {
        std::fputs(procpcap::helpText().c_str(), stdout);
        return 0;
    }
    if (parsed.opts.showVersion) {
        std::puts(PROCPCAP_VERSION_STRING);
        return 0;
    }
    if (!parsed.ok) {
        std::fprintf(stderr, "procpcap: %s\n", parsed.error.c_str());
        std::fprintf(stderr, "Try 'procpcap --help'.\n");
        return 2;
    }

    return procpcap::runCapture(parsed.opts);
}
