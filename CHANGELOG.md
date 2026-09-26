# Changelog

All notable changes to procpcap are recorded here. This project follows
[Semantic Versioning](https://semver.org/).

## [1.0.1] - 2026-09-26

### Fixed

- **`--name` now captures processes that start after launch.** If nothing
  matched at startup, procpcap said it was waiting for a match, but it never
  checked the names of processes that started later. It now checks each new
  process when it opens its first connection. With `--children`, a process is
  also captured when an ancestor's name matches, even if that ancestor started
  later. New unit tests cover these rules with a fake process table.
- **Fewer process lookups.** A check takes one process snapshot and records an
  answer for every process in it. A pid that did not match is checked again
  after 250 ms, so a matching process that reuses the pid is still found.
  Before, `--children` took a snapshot for each step up the parent chain on
  every connection event from a process it was not capturing.
- **Names after pid reuse.** A newly matched process is labeled with its own
  name, even if its pid belonged to another process earlier in the run.
- **README fixes.** The sample output is a real Firefox capture, not
  `procpcap-synth` output. The README now says that a packet still unmatched
  after 100 ms is dropped, and the YouTube link is updated.

## [1.0.0] - 2026-09-25

The first release.

### Added

- **Per-process capture.** Select a process by `--pid` (repeatable) or by
  `--name <substr>`, add `--children` to include its descendants, and procpcap
  writes only that process's packets. It maps each packet to a process through a
  WinDivert FLOW-layer handle opened `SNIFF | RECV_ONLY`.
- **Seeding for flows that predate the run.** The FLOW layer reports only flows
  created after its handle opens, so procpcap seeds the flow table at startup
  from `GetExtendedTcpTable` and `GetExtendedUdpTable`, for IPv4 and IPv6. UDP
  seeds are matched on local port.
- **Correct attribution under PID reuse.** The flow table is keyed on the
  5-tuple and the flow's start time, so a `FLOW_DELETED` for an old flow cannot
  remove a newer flow that reused the same 5-tuple, and the process name is the
  one captured when the flow was established.
- **A pcapng writer** with a `LINKTYPE_RAW` interface block, since WinDivert
  delivers bare IP packets, and an `opt_comment` (option code 1) on every packet
  holding the owning pid and process name.
- **Streaming to Wireshark.** `-o <file.pcapng>` writes a file; `-w -` streams
  pcapng to stdout for `wireshark -k -i -`.
- **A live stats line** on stderr: packets per second, bytes per second, the
  count of distinct endpoints, and the mean payload entropy.
- **A Wireshark Lua dissector template** in `examples/` for walking a game's own
  packet format.
- Unit tests over the pcapng writer (byte-exact against hand-built blocks), the
  flow table, the IP parser, the entropy calculation, the stats accumulator and
  the argument parser.

[1.0.1]: https://github.com/HeathHowren/procpcap/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/HeathHowren/procpcap/releases/tag/v1.0.0
