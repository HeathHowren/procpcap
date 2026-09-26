#include "core/Cli.h"

#include "Version.h"

#include <charconv>

namespace procpcap {

namespace {

// Parse a base-10 uint32 with no leading sign or junk. Returns false on failure.
bool parseU32(const std::string& s, uint32_t& out) {
    if (s.empty())
        return false;
    for (char c : s)
        if (c < '0' || c > '9')
            return false;
    const char* first = s.data();
    const char* last = s.data() + s.size();
    auto [ptr, ec] = std::from_chars(first, last, out);
    return ec == std::errc() && ptr == last;
}

void setOutput(CliOptions& o, const std::string& target) {
    o.output = target;
    o.toStdout = (target == "-");
}

} // namespace

CliResult parseCli(const std::vector<std::string>& args) {
    CliResult r;
    CliOptions& o = r.opts;
    bool haveOutput = false;

    for (size_t i = 0; i < args.size(); ++i) {
        const std::string& a = args[i];

        auto needValue = [&](std::string& dst) -> bool {
            if (i + 1 >= args.size()) {
                r.error = a + " needs a value";
                return false;
            }
            dst = args[++i];
            return true;
        };

        if (a == "--help" || a == "-h") {
            o.showHelp = true;
            r.ok = true;
            return r;
        }
        if (a == "--version") {
            o.showVersion = true;
            r.ok = true;
            return r;
        }
        if (a == "--pid") {
            std::string v;
            if (!needValue(v))
                return r;
            uint32_t pid = 0;
            if (!parseU32(v, pid)) {
                r.error = "--pid wants a number, got \"" + v + "\"";
                return r;
            }
            o.pids.push_back(pid);
        } else if (a == "--name") {
            if (!needValue(o.nameSubstr))
                return r;
            if (o.nameSubstr.empty()) {
                r.error = "--name wants a non-empty substring";
                return r;
            }
        } else if (a == "--children") {
            o.children = true;
        } else if (a == "-o" || a == "--out" || a == "-w") {
            std::string v;
            if (!needValue(v))
                return r;
            setOutput(o, v);
            haveOutput = true;
        } else {
            r.error = "unknown argument \"" + a + "\"";
            return r;
        }
    }

    if (o.pids.empty() && o.nameSubstr.empty()) {
        r.error = "select a process with --pid or --name";
        return r;
    }
    if (o.children && o.pids.empty() && o.nameSubstr.empty()) {
        r.error = "--children needs a --pid or --name to start from";
        return r;
    }
    if (!haveOutput) {
        r.error = "no output; give -o <file.pcapng> or -w - to stream to stdout";
        return r;
    }

    r.ok = true;
    return r;
}

std::string helpText() {
    return "procpcap " PROCPCAP_VERSION_STRING " - per-process packet capture on Windows\n"
           "\n"
           "Captures the traffic of one process (or a set of them) and writes a\n"
           "pcapng file you open in Wireshark. Each packet is tagged with the owning\n"
           "process id and name. Requires Administrator and the WinDivert driver.\n"
           "\n"
           "Usage:\n"
           "  procpcap --pid <n> [--pid <n> ...] -o <file.pcapng>\n"
           "  procpcap --name <substr> [--children] -o <file.pcapng>\n"
           "  procpcap --pid <n> -w -            (stream pcapng to stdout for a pipe)\n"
           "\n"
           "Selectors (at least one required):\n"
           "  --pid <n>        capture this process id; may be repeated\n"
           "  --name <substr>  capture every process whose image name contains <substr>\n"
           "  --children       also capture processes descended from the selected ones\n"
           "\n"
           "Output (one required):\n"
           "  -o <file>        write the capture to <file.pcapng>\n"
           "  -w <file>        same as -o; -w - streams to stdout\n"
           "\n"
           "Other:\n"
           "  -h, --help       show this help\n"
           "      --version    show the version\n"
           "\n"
           "Example, piping straight into Wireshark:\n"
           "  procpcap --name game -w - | wireshark -k -i -\n";
}

} // namespace procpcap
