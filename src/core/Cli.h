#ifndef PROCPCAP_CLI_H
#define PROCPCAP_CLI_H

#include <cstdint>
#include <string>
#include <vector>

namespace procpcap {

// The parsed command line.
struct CliOptions {
    std::vector<uint32_t> pids; // --pid, repeatable
    std::string nameSubstr;     // --name, empty if unset
    bool children = false;      // --children
    std::string output;         // -o / -w target; "-" means stdout
    bool toStdout = false;      // output target is stdout
    bool showHelp = false;      // --help / -h
    bool showVersion = false;   // --version
};

struct CliResult {
    bool ok = false;
    std::string error; // set when ok is false
    CliOptions opts;
};

// Parse arguments (excluding argv[0]). --help and --version short-circuit: the
// result is ok with the flag set and nothing else is required. Otherwise a valid
// command line needs at least one selector (--pid or --name) and an output
// target (-o or -w). Errors are returned, never printed.
CliResult parseCli(const std::vector<std::string>& args);

// The usage text shown by --help.
std::string helpText();

} // namespace procpcap

#endif // PROCPCAP_CLI_H
