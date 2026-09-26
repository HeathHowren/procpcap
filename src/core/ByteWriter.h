#ifndef PROCPCAP_BYTEWRITER_H
#define PROCPCAP_BYTEWRITER_H

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace procpcap {

// A little-endian byte sink. pcapng on a little-endian host is written with the
// 0x1A2B3C4D byte-order magic, so every field below is emitted little-endian
// regardless of the host, which keeps the output deterministic for the tests.
class ByteWriter {
public:
    void u8(uint8_t v) { buf_.push_back(v); }

    void u16(uint16_t v) {
        buf_.push_back(static_cast<uint8_t>(v & 0xFF));
        buf_.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    }

    void u32(uint32_t v) {
        for (int i = 0; i < 4; ++i)
            buf_.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
    }

    void u64(uint64_t v) {
        for (int i = 0; i < 8; ++i)
            buf_.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
    }

    void bytes(const uint8_t* p, size_t n) { buf_.insert(buf_.end(), p, p + n); }

    void bytes(const std::string& s) { buf_.insert(buf_.end(), s.begin(), s.end()); }

    // Pad with zero bytes until the total size is a multiple of four, as every
    // pcapng block and option requires.
    void pad4() {
        while (buf_.size() % 4 != 0)
            buf_.push_back(0);
    }

    // Overwrite four bytes already written (used to backfill a block's total
    // length once the block is complete).
    void patchU32(size_t offset, uint32_t v) {
        for (int i = 0; i < 4; ++i)
            buf_[offset + static_cast<size_t>(i)] = static_cast<uint8_t>((v >> (8 * i)) & 0xFF);
    }

    size_t size() const { return buf_.size(); }
    const std::vector<uint8_t>& data() const { return buf_; }
    std::vector<uint8_t> take() { return std::move(buf_); }

private:
    std::vector<uint8_t> buf_;
};

// Round n up to the next multiple of four.
inline size_t roundUp4(size_t n) { return (n + 3) & ~static_cast<size_t>(3); }

} // namespace procpcap

#endif // PROCPCAP_BYTEWRITER_H
