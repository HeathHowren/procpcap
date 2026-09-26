#ifndef PROCPCAP_CAPTURE_H
#define PROCPCAP_CAPTURE_H

#include "core/Cli.h"

namespace procpcap {

// Signal a running capture to stop. Set from the console control handler so a
// Ctrl+C flushes and closes the file cleanly.
void requestStop();

// Run a capture to completion (until stopped). Opens the WinDivert FLOW and
// NETWORK handles, seeds the flow table, writes pcapng to the chosen output, and
// prints a live stats line to stderr. Returns a process exit code; a non-zero
// value comes with an explanation already written to stderr.
//
// This needs Administrator and the WinDivert driver, so it cannot run in an
// unprivileged environment; the exit code and message say why when it cannot.
int runCapture(const CliOptions& opts);

} // namespace procpcap

#endif // PROCPCAP_CAPTURE_H
