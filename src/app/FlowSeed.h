#ifndef PROCPCAP_FLOWSEED_H
#define PROCPCAP_FLOWSEED_H

#include "app/ProcessInfo.h"
#include "core/FlowTable.h"

namespace procpcap {

// Seed the flow table from the operating system's own connection tables at
// startup. The FLOW layer only reports flows created after its handle is opened,
// so any connection already in progress would otherwise have no PID. This reads
// GetExtendedTcpTable and GetExtendedUdpTable (IPv4 and IPv6) and inserts a
// seeded record for each row. UDP rows carry only a local address and port, so
// they are matched on local port at lookup time.
//
// Returns the number of rows seeded.
size_t seedFlowTable(FlowTable& table, ProcessResolver& resolver);

} // namespace procpcap

#endif // PROCPCAP_FLOWSEED_H
