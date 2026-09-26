#include "core/Entropy.h"

#include <array>
#include <cmath>

namespace procpcap {

double shannonEntropy(const uint8_t* data, size_t len) {
    if (data == nullptr || len == 0)
        return 0.0;

    std::array<size_t, 256> counts{};
    for (size_t i = 0; i < len; ++i)
        ++counts[data[i]];

    const double total = static_cast<double>(len);
    double entropy = 0.0;
    for (size_t c : counts) {
        if (c == 0)
            continue;
        const double p = static_cast<double>(c) / total;
        entropy -= p * std::log2(p);
    }
    return entropy;
}

} // namespace procpcap
