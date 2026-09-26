#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_floating_point.hpp>

#include "core/Entropy.h"

#include <vector>

using namespace procpcap;
using Catch::Matchers::WithinAbs;

TEST_CASE("entropy of an empty buffer is zero", "[entropy]") { REQUIRE(shannonEntropy(nullptr, 0) == 0.0); }

TEST_CASE("entropy of a single repeated byte is zero", "[entropy]") {
    std::vector<uint8_t> data(256, 0x41);
    REQUIRE_THAT(shannonEntropy(data.data(), data.size()), WithinAbs(0.0, 1e-9));
}

TEST_CASE("two equally likely symbols give one bit per byte", "[entropy]") {
    std::vector<uint8_t> data;
    for (int i = 0; i < 128; ++i) {
        data.push_back(0x00);
        data.push_back(0xFF);
    }
    REQUIRE_THAT(shannonEntropy(data.data(), data.size()), WithinAbs(1.0, 1e-9));
}

TEST_CASE("all 256 byte values equally likely give eight bits per byte", "[entropy]") {
    std::vector<uint8_t> data(256);
    for (int i = 0; i < 256; ++i)
        data[static_cast<size_t>(i)] = static_cast<uint8_t>(i);
    REQUIRE_THAT(shannonEntropy(data.data(), data.size()), WithinAbs(8.0, 1e-9));
}

TEST_CASE("entropy stays within range for a mixed buffer", "[entropy]") {
    const char* text = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    double e = shannonEntropy(reinterpret_cast<const uint8_t*>(text), std::char_traits<char>::length(text));
    REQUIRE(e > 0.0);
    REQUIRE(e < 8.0);
}
