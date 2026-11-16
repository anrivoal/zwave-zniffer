// SPDX-License-Identifier: BSD-3-Clause
#include "zniffer/serial.hpp"

#include <algorithm>

namespace zw::zniffer {
namespace {

// A zero result means more bytes are needed. A negative result means a bad
// prefix and the caller must advance one byte before retrying.
int frame_size(const std::vector<std::uint8_t>& p) {
    if (p.empty()) return 0;
    if (p[0] == 0x3b) {
        if (p.size() < 6) return 0;
        if (p[3] != 0x23) return -1;
        if (p[5] == 0x2e) return 6;
        if (p[5] != 0x2c && p[5] != 0x57) return -1;
        for (std::size_t at = 7; at < p.size(); at += 2) {
            if (p[at] == 0x2e) return static_cast<int>(at + 1);
            if (p[at] != 0x2c && p[at] != 0x57) return -1;
        }
        return p.size() > 512 ? -1 : 0;
    }
    if (p[0] != 0x21) return -1;
    if (p.size() < 2) return 0;
    const auto type = p[1];
    if (type == 0x05) return p.size() >= 7 ? 7 : 0;
    if (type != 0x01 && type != 0x04) return -1;
    if (p.size() < 8) return 0;
    if (type == 0x04) {
        // SOF, wakeup-start, 2-byte time, speed/channel, frequency, RSSI,
        // beam type, destination, version, optional Home ID hash.
        if (p.size() < 10) return 0;
        return p[9] == 1 ? (p.size() >= 11 ? 11 : 0) : 10;
    }
    if (p[7] != 0x21) return -1;
    if (p.size() < 9) return 0;
    if (p[8] == 0x02) return p.size() >= 11 ? 11 : 0;
    if (p[8] != 0x03) return -1;
    if (p.size() < 10) return 0;
    const auto length = p[9];
    if (length < 3 || length == 255) return -1;
    return p.size() >= static_cast<std::size_t>(10 + length) ? 10 + length : 0;
}

SerialFrame decode(std::span<const std::uint8_t> raw, const zlf::Record& record,
                   std::uint64_t first_offset, std::uint64_t first_time) {
    SerialFrame frame;
    frame.zlf_offset = first_offset;
    frame.datetime_binary = first_time;
    frame.session_id = record.session_id;
    frame.raw.assign(raw.begin(), raw.end());
    if (raw[0] == 0x3b) {
        frame.api_version = 3;
        frame.frame_type = raw[5] == 0x57 ? 0x57 : 0x03;
        frame.system_time = static_cast<std::uint16_t>((raw[1] << 8) | raw[2]);
        frame.speed = raw[4];
        for (std::size_t at = 6; at + 1 < raw.size(); at += 2) {
            frame.payload.push_back(raw[at]);
            if (raw[at + 1] == 0x57) frame.frame_type = 0x57;
        }
    } else {
        frame.api_version = 4;
        frame.frame_type = raw[1] == 0x01 ? raw[8] : raw[1];
        frame.system_time = static_cast<std::uint16_t>((raw[2] << 8) | raw[3]);
        if (raw[1] != 0x05) {
            frame.speed = raw[4] & 0x1f;
            frame.channel = raw[4] >> 5;
            frame.frequency = raw[5];
            frame.rssi = raw[6];
            const auto start = raw[1] == 0x01 && raw[8] == 0x03 ? 10 :
                               raw[1] == 0x01 ? 9 : 7;
            frame.payload.assign(raw.begin() + start, raw.end());
        } else frame.rssi = raw[4];
    }
    return frame;
}

} // namespace

std::vector<SerialFrame> SerialDecoder::feed(const zlf::Record& record) {
    std::vector<SerialFrame> result;
    if (record.api_type != static_cast<std::uint8_t>(zlf::ApiType::zniffer)) return result;
    auto& state = sessions_[record.session_id];
    if (state.pending.empty()) {
        state.first_offset = record.offset;
        state.first_time = record.datetime_binary;
    }
    state.pending.insert(state.pending.end(), record.data.begin(), record.data.end());
    while (!state.pending.empty()) {
        const auto size = frame_size(state.pending);
        if (size == 0) break;
        if (size < 0) {
            state.pending.erase(state.pending.begin());
            state.first_offset = record.offset;
            state.first_time = record.datetime_binary;
            continue;
        }
        result.push_back(decode(std::span(state.pending.data(), static_cast<std::size_t>(size)),
                                record, state.first_offset, state.first_time));
        state.pending.erase(state.pending.begin(), state.pending.begin() + size);
        state.first_offset = record.offset;
        state.first_time = record.datetime_binary;
    }
    if (state.pending.size() > 512) state.pending.clear();
    return result;
}

void SerialDecoder::reset(std::uint8_t session_id) { sessions_.erase(session_id); }

} // namespace zw::zniffer
