# Changelog

All notable changes to procpcap are recorded here. This project follows
[Semantic Versioning](https://semver.org/).

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
