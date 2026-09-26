#include <catch2/catch_test_macros.hpp>

#include "core/TargetSelector.h"

#include <chrono>
#include <string>

using namespace procpcap;
using namespace std::chrono_literals;

namespace {

// A process table the test edits between checks, plus a count of how many
// snapshots the selector took of it.
struct FakeSystem {
    ProcessTable table;
    int snapshots = 0;

    void start(uint32_t pid, uint32_t parent, const std::string& image) { table[pid] = ProcessEntry{parent, image}; }
    void exit(uint32_t pid) { table.erase(pid); }

    TargetSelector selector() {
        return TargetSelector([this] {
            ++snapshots;
            return table;
        });
    }
};

CliOptions byName(const std::string& name, bool children = false) {
    CliOptions o;
    o.nameSubstr = name;
    o.children = children;
    return o;
}

CliOptions byPid(uint32_t pid, bool children = false) {
    CliOptions o;
    o.pids.push_back(pid);
    o.children = children;
    return o;
}

const TargetSelector::Clock::time_point t0{};

} // namespace

TEST_CASE("a matching process that starts after startup is a target", "[targets]") {
    FakeSystem sys;
    sys.start(4, 0, "System");
    sys.start(100, 4, "explorer.exe");
    TargetSelector sel = sys.selector();
    sel.resolve(byName("game"), t0);
    REQUIRE(sel.targetCount() == 0); // nothing matches yet: procpcap waits

    sys.start(200, 100, "Game.exe");
    REQUIRE(sel.isTarget(200, t0 + 1s));
}

TEST_CASE("a later process that does not match is not a target", "[targets]") {
    FakeSystem sys;
    sys.start(100, 4, "explorer.exe");
    TargetSelector sel = sys.selector();
    sel.resolve(byName("game"), t0);

    sys.start(300, 100, "notepad.exe");
    REQUIRE_FALSE(sel.isTarget(300, t0 + 1s));
}

TEST_CASE("name matching is a case-insensitive substring match", "[targets]") {
    FakeSystem sys;
    sys.start(200, 4, "MyGameClient.EXE");
    sys.start(201, 4, "gam.exe");
    TargetSelector sel = sys.selector();
    sel.resolve(byName("gAmE"), t0);
    REQUIRE(sel.isTarget(200, t0));
    REQUIRE_FALSE(sel.isTarget(201, t0));
}

TEST_CASE("with --children, a child of a later matching process is a target", "[targets]") {
    FakeSystem sys;
    sys.start(100, 4, "explorer.exe");
    TargetSelector sel = sys.selector();
    sel.resolve(byName("launcher", true), t0);

    sys.start(200, 100, "launcher.exe");
    sys.start(300, 200, "game.exe");
    sys.start(400, 300, "crashhandler.exe");
    REQUIRE(sel.isTarget(300, t0 + 1s));
    REQUIRE(sel.isTarget(400, t0 + 1s)); // grandchild
}

TEST_CASE("without --children, a child of a matching process is not a target", "[targets]") {
    FakeSystem sys;
    TargetSelector sel = sys.selector();
    sel.resolve(byName("launcher"), t0);

    sys.start(200, 100, "launcher.exe");
    sys.start(300, 200, "game.exe");
    sys.start(301, 200, "launcher-helper.exe");
    REQUIRE(sel.isTarget(200, t0 + 1s));
    REQUIRE_FALSE(sel.isTarget(300, t0 + 1s));
    REQUIRE(sel.isTarget(301, t0 + 1s)); // its own name matches
}

TEST_CASE("with --children, a child stays a target after its matching parent exits", "[targets]") {
    FakeSystem sys;
    sys.start(200, 100, "launcher.exe");
    TargetSelector sel = sys.selector();
    sel.resolve(byName("launcher", true), t0);
    REQUIRE(sel.targetCount() == 1);

    // The launcher starts the game and quits before the game connects.
    sys.start(300, 200, "game.exe");
    sys.exit(200);
    REQUIRE(sel.isTarget(300, t0 + 1s));
}

TEST_CASE("targets given with --pid work without any snapshot", "[targets]") {
    FakeSystem sys;
    sys.start(4242, 1, "game.exe");
    sys.start(5000, 1, "game-too.exe");
    TargetSelector sel = sys.selector();
    sel.resolve(byPid(4242), t0);
    REQUIRE(sel.targetCount() == 1);
    REQUIRE(sel.isTarget(4242, t0));
    REQUIRE_FALSE(sel.isTarget(5000, t0));
    REQUIRE_FALSE(sel.isTarget(0, t0));
    REQUIRE(sys.snapshots == 0);
}

TEST_CASE("with --children, a child of a --pid target is a target", "[targets]") {
    FakeSystem sys;
    sys.start(4242, 1, "launcher.exe");
    sys.start(4300, 4242, "game.exe");
    TargetSelector sel = sys.selector();
    sel.resolve(byPid(4242, true), t0);
    REQUIRE(sel.targetCount() == 2); // found at startup

    sys.start(4400, 4300, "updater.exe");
    REQUIRE(sel.isTarget(4400, t0 + 1s)); // started later
    REQUIRE_FALSE(sel.isTarget(1, t0 + 1s));
}

TEST_CASE("a pid that is not a target is looked up at most once per interval", "[targets]") {
    FakeSystem sys;
    sys.start(300, 4, "notepad.exe");
    TargetSelector sel = sys.selector();
    sel.resolve(byName("game"), t0);
    REQUIRE(sys.snapshots == 1);

    // Many flow events inside the interval reuse the answer from startup.
    for (int i = 0; i < 100; ++i)
        REQUIRE_FALSE(sel.isTarget(300, t0 + 10ms));
    REQUIRE(sys.snapshots == 1);

    // After the interval, one new snapshot answers again.
    REQUIRE_FALSE(sel.isTarget(300, t0 + TargetSelector::kRecheckAfter));
    REQUIRE_FALSE(sel.isTarget(300, t0 + TargetSelector::kRecheckAfter + 10ms));
    REQUIRE(sys.snapshots == 2);
}

TEST_CASE("a target is remembered without another snapshot", "[targets]") {
    FakeSystem sys;
    TargetSelector sel = sys.selector();
    sel.resolve(byName("game"), t0);
    sys.start(200, 4, "game.exe");
    REQUIRE(sel.isTarget(200, t0 + 1s));
    int taken = sys.snapshots;
    REQUIRE(sel.isTarget(200, t0 + 1h));
    REQUIRE(sys.snapshots == taken);
}

TEST_CASE("a pid reused by a matching process is picked up after the interval", "[targets]") {
    FakeSystem sys;
    sys.start(300, 4, "notepad.exe");
    TargetSelector sel = sys.selector();
    sel.resolve(byName("game"), t0);
    REQUIRE_FALSE(sel.isTarget(300, t0));

    // notepad exits and a matching process takes the same pid. Inside the
    // interval the old answer stands; after it, the new process is found.
    sys.exit(300);
    sys.start(300, 4, "game.exe");
    REQUIRE_FALSE(sel.isTarget(300, t0 + 10ms));
    REQUIRE(sel.isTarget(300, t0 + TargetSelector::kRecheckAfter));
}

TEST_CASE("a parent-pid loop does not hang the chain walk", "[targets]") {
    FakeSystem sys;
    sys.start(500, 600, "a.exe");
    sys.start(600, 500, "b.exe");
    sys.start(700, 700, "self.exe");
    TargetSelector sel = sys.selector();
    sel.resolve(byName("game", true), t0);
    REQUIRE_FALSE(sel.isTarget(500, t0));
    REQUIRE_FALSE(sel.isTarget(700, t0));
}
