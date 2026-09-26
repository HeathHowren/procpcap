#include <catch2/catch_test_macros.hpp>

#include "core/Cli.h"

#include <string>
#include <vector>

using namespace procpcap;

namespace {
CliResult parse(std::vector<std::string> args) { return parseCli(args); }
} // namespace

TEST_CASE("a pid and an output file parse", "[cli]") {
    auto r = parse({"--pid", "1234", "-o", "game.pcapng"});
    REQUIRE(r.ok);
    REQUIRE(r.opts.pids.size() == 1);
    REQUIRE(r.opts.pids[0] == 1234);
    REQUIRE(r.opts.output == "game.pcapng");
    REQUIRE_FALSE(r.opts.toStdout);
}

TEST_CASE("the pid selector may be repeated", "[cli]") {
    auto r = parse({"--pid", "1", "--pid", "2", "--pid", "3", "-o", "x.pcapng"});
    REQUIRE(r.ok);
    REQUIRE(r.opts.pids == std::vector<uint32_t>{1, 2, 3});
}

TEST_CASE("name substring with children parses", "[cli]") {
    auto r = parse({"--name", "game", "--children", "-o", "x.pcapng"});
    REQUIRE(r.ok);
    REQUIRE(r.opts.nameSubstr == "game");
    REQUIRE(r.opts.children);
}

TEST_CASE("writing to a dash streams to stdout", "[cli]") {
    auto r = parse({"--pid", "5", "-w", "-"});
    REQUIRE(r.ok);
    REQUIRE(r.opts.toStdout);
    REQUIRE(r.opts.output == "-");
}

TEST_CASE("help and version short-circuit before other checks", "[cli]") {
    auto h = parse({"--help"});
    REQUIRE(h.ok);
    REQUIRE(h.opts.showHelp);

    auto v = parse({"--version"});
    REQUIRE(v.ok);
    REQUIRE(v.opts.showVersion);
}

TEST_CASE("a selector is required", "[cli]") {
    auto r = parse({"-o", "x.pcapng"});
    REQUIRE_FALSE(r.ok);
    REQUIRE_FALSE(r.error.empty());
}

TEST_CASE("an output target is required", "[cli]") {
    auto r = parse({"--pid", "1234"});
    REQUIRE_FALSE(r.ok);
    REQUIRE_FALSE(r.error.empty());
}

TEST_CASE("a non-numeric pid is an error", "[cli]") {
    auto r = parse({"--pid", "notanumber", "-o", "x.pcapng"});
    REQUIRE_FALSE(r.ok);
}

TEST_CASE("a flag missing its value is an error, not a crash", "[cli]") {
    REQUIRE_FALSE(parse({"--pid"}).ok);
    REQUIRE_FALSE(parse({"--name"}).ok);
    REQUIRE_FALSE(parse({"--pid", "1", "-o"}).ok);
}

TEST_CASE("an unknown argument is reported", "[cli]") {
    auto r = parse({"--pid", "1", "-o", "x.pcapng", "--frobnicate"});
    REQUIRE_FALSE(r.ok);
    REQUIRE(r.error.find("frobnicate") != std::string::npos);
}

TEST_CASE("help text names the required options", "[cli]") {
    std::string help = helpText();
    REQUIRE(help.find("--pid") != std::string::npos);
    REQUIRE(help.find("--name") != std::string::npos);
    REQUIRE(help.find("--children") != std::string::npos);
    REQUIRE(help.find("-w -") != std::string::npos);
}
