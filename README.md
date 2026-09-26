<p align="center">
  <img src="docs/logo.svg" width="96" alt="procpcap logo">
</p>

# procpcap

Per-process packet capture on Windows, written to a pcapng you open in Wireshark.

[![CI](https://github.com/HeathHowren/procpcap/actions/workflows/ci.yml/badge.svg)](https://github.com/HeathHowren/procpcap/actions/workflows/ci.yml)

Wireshark captures a whole interface. It cannot show you one program's traffic on
its own, because Windows does not tag packets with a process once they reach the
network layer. procpcap does that tagging. It watches the WinDivert FLOW layer to
learn which process owns each connection, sniffs the network layer, keeps only
the packets that belong to the process you asked for, and writes a standard
pcapng. Every packet carries a comment with the owning process id and name, so
the mapping survives in the file.

procpcap is a diagnostic capture tool, like a focused Wireshark for one process.
It reads traffic; it does not modify, block or inject it, and it is for your own
machine and your own traffic.

procpcap is written by Heath Howren
([Cyborg Elf](https://www.youtube.com/cyborgelf)) of
[Game Reversal Club](https://gamereversal.club). It is the first step in the
netcode chapters of
[*The Game Hacker's Handbook*](https://gamereversal.club/books/game-hackers-handbook/):
capture one game's packets, then read them.

```
PS> procpcap --name firefox -o procpcap-test.pcapng
seeded 13 existing flow(s) from the connection table.
      0 pkt/s          0 B/s      27 endpoints  entropy 5.70  (15148 packets)
capture stopped. 15148 packets written.
```

*A real capture of Firefox browsing for two and a half minutes on Windows 10,
from an elevated prompt. All 15,148 packets in the file carry the comment
`pid 28988 firefox.exe`: 11,634 IPv6 and 3,514 IPv4, to 28 addresses. The
stats line is the last one printed, after Ctrl+C.*

## Before you start

- **Administrator is required.** WinDivert loads a kernel driver, which needs an
  elevated prompt. procpcap says so and exits if it is not elevated.
- **The WinDivert driver can be blocked.** `WinDivert64.sys` is a signed but
  third-party driver. Antivirus software flags it often, and Windows can refuse
  to load it when Memory Integrity (HVCI) or Smart App Control is on. If the
  driver will not load, procpcap reports the error; you may have to allow the
  driver in your security software or turn those features off to use it.
- `WinDivert.dll` and `WinDivert64.sys` must sit next to `procpcap.exe`. The
  release zip and the build both put them there.

## What it does

- **Captures one process, or a set of them.** Choose by `--pid` (repeatable) or
  by `--name <substr>`. `--name` also picks up matching processes that start
  after the capture begins. Add `--children` to include processes spawned by the
  ones you picked, so a launcher and its game are captured together.
- **Attributes every packet to a process.** A WinDivert FLOW-layer handle,
  opened `SNIFF | RECV_ONLY`, reports which process owns each 5-tuple. A packet's
  owner is written into its pcapng comment as `pid <n> <name>`.
- **Sees connections that were already open.** The FLOW layer only reports flows
  created after it starts, so procpcap seeds its flow table at startup from the
  Windows TCP and UDP tables (`GetExtendedTcpTable`, `GetExtendedUdpTable`, IPv4
  and IPv6). UDP has no remote in that table, so UDP is seeded on local port.
- **Does not confuse a reused connection.** The flow table is keyed on the
  5-tuple and the flow's start time. A late close event for an old flow cannot
  remove a new flow that reused the same 5-tuple, and the process name is the one
  recorded when the flow opened, so a process id reused after a process exits is
  not mis-attributed.
- **Writes standard pcapng.** The interface block is `LINKTYPE_RAW`, because
  WinDivert delivers bare IP packets with no link-layer header. Wireshark reads
  the file directly.
- **Pipes to Wireshark.** `-o <file.pcapng>` writes a file; `-w -` streams pcapng
  to stdout for `wireshark -k -i -`.
- **Shows live stats.** One line per second on stderr: packets per second, bytes
  per second, the count of distinct endpoints, and the mean payload entropy. High
  entropy means the payload is encrypted or compressed; low entropy means there
  is something to read.

It handles TCP and UDP, IPv4 and IPv6. It does not reassemble TCP streams; that
is Wireshark's job once the file is open. It captures on the local host only.

Packets are written in the order procpcap attributes them, not strictly in time
order. A packet that arrives before its connection is matched to a process is
held for up to 100 ms and written when the match comes in, so it can land after
a later packet. In the Firefox capture above, the largest step back was 25 ms.
Every packet keeps its own timestamp. Run Wireshark's `reordercap` on the file
if a tool needs it sorted.

A packet whose connection is still not matched to a selected process after
100 ms is dropped. It is not written or counted in the stats, which is how other
processes' traffic is left out.

## Download

Get the latest zip from
[Releases](https://github.com/HeathHowren/procpcap/releases) and extract it
anywhere. It contains:

```
procpcap.exe            the tool
WinDivert.dll           WinDivert user-mode library (unmodified upstream binary)
WinDivert64.sys         WinDivert kernel driver (unmodified upstream binary)
WinDivert-LICENSE.txt   WinDivert's dual LGPL/GPL license
examples\               a Wireshark Lua dissector template
LICENSE, README.md, CHANGELOG.md, THIRD_PARTY_NOTICES.md
```

procpcap.exe is built with the static C runtime, so it needs no VC++
redistributable. The binaries are unsigned; WinDivert's own driver is signed by
its author. See the note above on why the driver may still be blocked.

## Quick start

Open an Administrator terminal in the extracted folder.

```
:: capture one process by id
procpcap --pid 4242 -o game.pcapng

:: capture every process whose name contains "game", and their children
procpcap --name game --children -o game.pcapng

:: stream straight into Wireshark
procpcap --pid 4242 -w - | wireshark -k -i -
```

Press Ctrl+C to stop. procpcap flushes and closes the file, then prints how many
packets it wrote. Open the pcapng in Wireshark; each packet's owning process is
in the packet comment, shown in the packet details pane.

To decode a game's own protocol on top of UDP or TCP, start from
`examples\game-protocol.lua`, a Wireshark Lua dissector template with the fields
marked to fill in.

## Usage

```
procpcap --pid <n> [--pid <n> ...] -o <file.pcapng>
procpcap --name <substr> [--children] -o <file.pcapng>
procpcap --pid <n> -w -            (stream pcapng to stdout for a pipe)
```

| Option | Meaning |
|---|---|
| `--pid <n>` | Capture this process id. May be repeated. |
| `--name <substr>` | Capture every process whose image name contains `<substr>`, case insensitive. |
| `--children` | Also capture processes descended from the selected ones. |
| `-o <file>` | Write the capture to `<file.pcapng>`. |
| `-w <file>` | Same as `-o`; `-w -` streams pcapng to stdout. |
| `-h`, `--help` | Show help. |
| `--version` | Show the version. |

At least one selector (`--pid` or `--name`) and one output (`-o` or `-w`) are
required.

## Build

**Requirements:** Visual Studio 2022 with the C++ workload (MSVC v143) and CMake
3.28 or newer. The CMake that ships with Visual Studio is recent enough.

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

The first configure downloads WinDivert (the official release zip, pinned by
SHA-256) and Catch2 (pinned by tag). The tests run the pcapng writer, the flow
table, the IP parser, the entropy calculation, the stats accumulator, the
argument parser and the process selection rules, none of which need the driver
or Administrator:

```
100% tests passed, 0 tests failed out of 50
```

`procpcap-synth`, built alongside, writes a small synthetic pcapng and reads it
back. It checks the writer without the driver or Administrator.

To produce the release zip:

```powershell
cpack --config build/CPackConfig.cmake -C Release -B build/package
```

## License

MIT; see [LICENSE](LICENSE). procpcap uses WinDivert, which is dual-licensed
under the LGPLv3 or the GPLv2 and is used unmodified as a dynamically linked
library, so procpcap itself stays MIT. The release zip ships WinDivert's signed
binaries and its full license. Details are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
