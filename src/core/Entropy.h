#ifndef PROCPCAP_ENTROPY_H
#define PROCPCAP_ENTROPY_H

#include <cstddef>
#include <cstdint>

namespace procpcap {

// Shannon entropy of a byte buffer, in bits per byte, in the range [0, 8]. An
// empty buffer has entropy 0. High entropy (near 8) suggests encrypted or
// compressed payload; low entropy suggests plaintext or structure. Used for the
// mean-payload-entropy figure in the live stats line, a quick read on whether a
// protocol is in the clear.
double shannonEntropy(const uint8_t* data, size_t len);

} // namespace procpcap

#endif // PROCPCAP_ENTROPY_H
