// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "zniffer/zlf.hpp"

#include <cstdint>
#include <optional>
#include <unordered_map>
#include <vector>

namespace zw::zniffer {

struct BasicSerialFrame {
    std::vector<std::uint8_t> bytes;
    std::uint8_t marker{};
    std::optional<std::uint8_t> function;
    std::optional<std::uint8_t> frame_type;
    std::optional<bool> checksum_ok;
};

class BasicSerialDecoder {
public:
    std::vector<BasicSerialFrame> feed(const zlf::Record& record);
    void reset();

private:
    struct Stream {
        std::vector<std::uint8_t> pending;
    };
    std::unordered_map<unsigned, Stream> streams_;
};

} // namespace zw::zniffer
