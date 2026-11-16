// SPDX-License-Identifier: BSD-3-Clause
#include "zniffer/mpdu.hpp"

namespace zw::zniffer {
namespace {

std::uint32_t be32(std::span<const std::uint8_t> d) {
    return (static_cast<std::uint32_t>(d[0]) << 24) |
           (static_cast<std::uint32_t>(d[1]) << 16) |
           (static_cast<std::uint32_t>(d[2]) << 8) | d[3];
}

std::string type_name(std::uint8_t type) {
    switch (type) {
        case 1: return "Singlecast";
        case 2: return "Multicast";
        case 3: return "Acknowledgement";
        case 5: return "Explorer";
        case 8: return "Routed";
        default: return "Unknown";
    }
}

} // namespace

std::optional<MpduSummary> summarize_mpdu(const RadioFrame& frame) {
    const auto bytes = std::span<const std::uint8_t>(frame.mpdu);
    if (frame.diagnostic || frame.beam || bytes.size() < 9 || frame.protocol != 6)
        return std::nullopt;
    MpduSummary summary;
    summary.home_id = be32(bytes);
    // RAIL region IDs 12-17 are Long Range configurations. The two end-device
    // configurations expose only LR channels 0/1, which map to logical 3/4.
    summary.long_range = frame.region == 14 || frame.region == 17 ||
                         ((frame.region == 12 || frame.region == 13 ||
                           frame.region == 15 || frame.region == 16) && frame.channel >= 3);
    if (summary.long_range) {
        if (bytes.size() < 12) return std::nullopt;
        const auto nodes = (static_cast<std::uint32_t>(bytes[4]) << 16) |
                           (static_cast<std::uint32_t>(bytes[5]) << 8) | bytes[6];
        summary.source_node = static_cast<std::uint16_t>(nodes >> 12);
        summary.destination_node = static_cast<std::uint16_t>(nodes & 0x0fff);
        summary.header_type = bytes[8] & 0x07;
        summary.ack_requested = (bytes[8] & 0x80) != 0;
        summary.sequence = bytes[9];
    } else {
        const bool three_channel = frame.region == 7 || frame.region == 10;
        const auto destination_at = three_channel ? 9U : 8U;
        if (bytes.size() <= destination_at) return std::nullopt;
        summary.source_node = bytes[4];
        summary.header_type = bytes[5] & 0x0f;
        summary.ack_requested = (bytes[5] & (three_channel ? 0x80 : 0x40)) != 0;
        summary.sequence = three_channel ? bytes[8] : bytes[6] & 0x0f;
        if (summary.header_type == 1 || summary.header_type == 3 || summary.header_type == 8)
            summary.destination_node = bytes[destination_at];
    }
    summary.type_name = type_name(summary.header_type);
    return summary;
}

std::optional<bool> validate_mpdu_crc(const RadioFrame& frame) {
    const auto bytes = std::span<const std::uint8_t>(frame.mpdu);
    if (frame.diagnostic || frame.beam || bytes.size() < 10 || frame.protocol != 6)
        return std::nullopt;
    const bool three_channel = frame.region == 7 || frame.region == 10;
    const auto fcs = frame.fcs_bytes.value_or(three_channel || frame.channel == 0 ? 2 : 1);
    if (fcs != 1 && fcs != 2) return std::nullopt;
    if (bytes[7] != bytes.size() || bytes.size() <= fcs) return false;
    if (fcs == 1) {
        std::uint8_t sum = 0xff;
        for (std::size_t i = 0; i + 1 < bytes.size(); ++i) sum ^= bytes[i];
        return sum == bytes.back();
    }
    std::uint16_t crc = 0xffff;
    for (std::size_t i = 0; i + 2 < bytes.size(); ++i)
        for (int bit = 7; bit >= 0; --bit) {
            const bool carry = (crc & 0x8000) != 0;
            crc = static_cast<std::uint16_t>((crc << 1) | ((bytes[i] >> bit) & 1));
            if (carry) crc ^= 0x1021;
        }
    for (int bit = 0; bit < 16; ++bit) {
        const bool carry = (crc & 0x8000) != 0;
        crc = static_cast<std::uint16_t>(crc << 1);
        if (carry) crc ^= 0x1021;
    }
    return crc == static_cast<std::uint16_t>((bytes[bytes.size() - 2] << 8) | bytes.back());
}

} // namespace zw::zniffer
