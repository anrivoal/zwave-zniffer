// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "zniffer/radio.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace zw::zniffer {

struct MpduSummary {
    std::uint32_t home_id{};
    std::uint16_t source_node{};
    std::optional<std::uint16_t> destination_node;
    std::uint8_t header_type{};
    std::uint8_t sequence{};
    bool ack_requested{};
    bool long_range{};
    std::string type_name;
};

std::optional<MpduSummary> summarize_mpdu(const RadioFrame& frame);
std::optional<bool> validate_mpdu_crc(const RadioFrame& frame);

} // namespace zw::zniffer
