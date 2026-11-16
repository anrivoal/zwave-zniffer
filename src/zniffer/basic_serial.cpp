// SPDX-License-Identifier: BSD-3-Clause
#include "zniffer/basic_serial.hpp"

#include <algorithm>

namespace zw::zniffer {
namespace {

bool checksum(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 5 || bytes[0] != 0x01) return false;
    const bool extended = bytes[1] == 0;
    const auto length = extended ? bytes[2] : bytes[1];
    const auto payload_at = extended ? 3U : 2U;
    if (bytes.size() != payload_at + length || length < 3) return false;
    auto value = static_cast<std::uint8_t>(0xff ^ (extended ? length + 2 : length));
    for (std::size_t i = payload_at; i + 1 < bytes.size(); ++i) value ^= bytes[i];
    return value == bytes.back();
}

BasicSerialFrame make_frame(std::span<const std::uint8_t> bytes) {
    BasicSerialFrame frame;
    frame.bytes.assign(bytes.begin(), bytes.end());
    frame.marker = bytes[0];
    if (bytes[0] == 0x01) {
        const auto at = bytes[1] == 0 ? 3U : 2U;
        if (bytes.size() > at + 2) {
            frame.frame_type = bytes[at];
            frame.function = bytes[at + 1];
            frame.checksum_ok = checksum(bytes);
        }
    }
    return frame;
}

} // namespace

std::vector<BasicSerialFrame> BasicSerialDecoder::feed(const zlf::Record& record) {
    std::vector<BasicSerialFrame> result;
    if (record.api_type != static_cast<std::uint8_t>(zlf::ApiType::basic)) return result;
    auto& pending = streams_[(static_cast<unsigned>(record.session_id) << 1) |
                             (record.outgoing ? 1U : 0U)].pending;
    pending.insert(pending.end(), record.data.begin(), record.data.end());
    while (!pending.empty()) {
        if (pending[0] == 0x06 || pending[0] == 0x15 || pending[0] == 0x18) {
            result.push_back(make_frame(std::span(pending.data(), 1)));
            pending.erase(pending.begin());
            continue;
        }
        if (pending[0] != 0x01) {
            pending.erase(pending.begin());
            continue;
        }
        if (pending.size() < 2) break;
        const bool extended = pending[1] == 0;
        if (extended && pending.size() < 3) break;
        const auto length = extended ? pending[2] : pending[1];
        if (length < 3) {
            pending.erase(pending.begin());
            continue;
        }
        const auto total = static_cast<std::size_t>(length) + (extended ? 3 : 2);
        if (pending.size() < total) break;
        result.push_back(make_frame(std::span(pending.data(), total)));
        pending.erase(pending.begin(), pending.begin() + total);
    }
    if (pending.size() > 512) pending.clear();
    return result;
}

void BasicSerialDecoder::reset() { streams_.clear(); }

} // namespace zw::zniffer
