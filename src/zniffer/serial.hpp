// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "zniffer/zlf.hpp"
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace zw::zniffer {

struct SerialFrame {
    std::uint64_t zlf_offset{};
    std::uint64_t datetime_binary{};
    std::uint8_t session_id{};
    std::uint8_t api_version{}; // 3 or 4
    std::uint8_t frame_type{};
    std::uint16_t system_time{};
    std::uint8_t speed{};
    std::uint8_t channel{};
    std::uint8_t frequency{};
    std::uint8_t rssi{};
    std::vector<std::uint8_t> payload;
    std::vector<std::uint8_t> raw;
};

class SerialDecoder {
public:
    std::vector<SerialFrame> feed(const zlf::Record& record);
    void reset(std::uint8_t session_id);

private:
    struct State {
        std::vector<std::uint8_t> pending;
        std::uint64_t first_offset{};
        std::uint64_t first_time{};
    };
    std::unordered_map<std::uint8_t, State> sessions_;
};

} // namespace zw::zniffer
