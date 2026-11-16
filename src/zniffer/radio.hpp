// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "zniffer/zlf.hpp"
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace zw::zniffer {

struct RadioFrame {
    std::uint64_t zlf_offset{};
    std::uint64_t datetime_binary{};
    std::uint8_t session_id{};
    std::uint16_t dch_version{};
    std::uint16_t dch_message_type{};
    bool received{};
    bool diagnostic{};
    bool beam{};
    std::uint8_t region{};
    std::uint8_t channel{};
    std::uint8_t protocol{};
    std::optional<std::uint8_t> fcs_bytes;
    std::optional<int> rssi_dbm;
    std::vector<std::uint8_t> mpdu;
    std::string issue;
};

// Decodes every DCH packet in a ZLF PTI record. Unsupported radio packets
// remain visible as diagnostic rows with their bytes and an issue string.
std::vector<RadioFrame> decode_pti(const zlf::Record& record);

} // namespace zw::zniffer
