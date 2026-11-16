// SPDX-License-Identifier: BSD-3-Clause
#include "zniffer/radio.hpp"

namespace zw::zniffer {
namespace {

std::uint16_t le16(std::span<const std::uint8_t> d, std::size_t i) {
    return static_cast<std::uint16_t>(d[i] | (d[i + 1] << 8));
}

RadioFrame decode_one(std::span<const std::uint8_t> d, const zlf::Record& r) {
    RadioFrame out;
    out.zlf_offset = r.offset;
    out.datetime_binary = r.datetime_binary;
    out.session_id = r.session_id;
    out.diagnostic = r.api_type == static_cast<std::uint8_t>(zlf::ApiType::pti_diagnostic);
    out.mpdu.assign(d.begin(), d.end()); // Preserve bytes if parsing stops.
    if (d.size() < 5 || d[0] != 0x5b || d.back() != 0x5d || le16(d, 1) != d.size() - 2) {
        out.issue = "invalid DCH envelope";
        out.diagnostic = true;
        return out;
    }
    const auto body = d.subspan(3, d.size() - 4);
    if (body.size() < 2) {
        out.issue = "missing DCH version";
        out.diagnostic = true;
        return out;
    }
    out.dch_version = le16(body, 0);
    std::size_t pti_at = 0;
    if (out.dch_version == 0 || out.dch_version == 2) {
        if (body.size() < 11) out.issue = "short DCH v2 header";
        else {
            out.dch_message_type = le16(body, 8);
            pti_at = 11;
        }
    } else if (out.dch_version == 3) {
        if (body.size() < 18) out.issue = "short DCH v3 header";
        else {
            out.dch_message_type = le16(body, 10);
            pti_at = 18;
        }
    } else out.issue = "unsupported DCH version";
    if (!out.issue.empty()) {
        out.diagnostic = true;
        return out;
    }
    if (out.dch_version != 0 && out.dch_message_type != 0x29 && out.dch_message_type != 0x2a) {
        out.issue = "DCH message is not a radio packet";
        out.diagnostic = true;
        return out;
    }
    const auto pti = body.subspan(pti_at);
    if (pti.size() < 5 || (pti[0] != 0xf8 && pti[0] != 0xfc)) {
        out.issue = "unsupported PTI hardware start";
        out.diagnostic = true;
        return out;
    }
    out.received = pti[0] == 0xf8;
    const auto cfg = pti.back();
    const bool cfg_rx = (cfg & 0x40) != 0;
    const auto variable_len = static_cast<std::size_t>((cfg >> 3) & 7);
    const auto info_version = cfg & 7;
    if (cfg_rx != out.received) {
        out.issue = "PTI direction conflicts with appended info";
        out.diagnostic = true;
        return out;
    }
    bool has_sync = false;
    std::size_t radio_cfg_len = 0;
    if (out.received) {
        if (variable_len == 1 || variable_len == 5) {}
        else if (variable_len == 2 || variable_len == 6) radio_cfg_len = 1;
        else if (variable_len == 3 || variable_len == 7) radio_cfg_len = 2;
        else out.issue = "unsupported RX appended-info length";
        has_sync = variable_len >= 5;
    } else {
        if (variable_len == 0 || variable_len == 4) {}
        else if (variable_len == 1 || variable_len == 5) radio_cfg_len = 1;
        else if (variable_len == 2 || variable_len == 6) radio_cfg_len = 2;
        else out.issue = "unsupported TX appended-info length";
        has_sync = variable_len >= 4;
    }
    if (!out.issue.empty()) {
        out.diagnostic = true;
        return out;
    }
    const auto appended_len = variable_len + 3;
    if (pti.size() < 3 + appended_len) {
        out.issue = "truncated PTI appended info";
        out.diagnostic = true;
        return out;
    }
    const auto end_at = pti.size() - appended_len - 1;
    const auto expected_end = out.received ? 0xf9 : 0xfd;
    if (pti[end_at] != expected_end) {
        out.issue = "PTI frame did not complete successfully";
        out.diagnostic = true;
    }
    out.mpdu.assign(pti.begin() + 1, pti.begin() + end_at);
    out.beam = !out.mpdu.empty() && out.mpdu[0] == 0x55;
    std::size_t at = pti.size() - appended_len;
    if (out.received) {
        auto rssi = static_cast<int>(static_cast<std::int8_t>(pti[at++]));
        if (info_version == 1) rssi -= 0x32;
        out.rssi_dbm = rssi;
    }
    if (has_sync) at += 4;
    if (radio_cfg_len) {
        out.region = pti[at] & 0x1f;
        at += radio_cfg_len;
    }
    out.channel = pti[at] & 0x3f;
    out.protocol = pti[pti.size() - 2] & 0x0f;
    if (out.protocol != 6 && out.issue.empty()) {
        out.issue = "non-Z-Wave radio protocol";
        out.diagnostic = true;
    }
    return out;
}

} // namespace

std::vector<RadioFrame> decode_pti(const zlf::Record& record) {
    std::vector<RadioFrame> out;
    if (record.api_type != static_cast<std::uint8_t>(zlf::ApiType::pti) &&
        record.api_type != static_cast<std::uint8_t>(zlf::ApiType::pti_diagnostic)) return out;
    const auto data = std::span<const std::uint8_t>(record.data);
    std::size_t at = 0;
    while (at < data.size()) {
        if (data.size() - at < 4 || data[at] != 0x5b) {
            auto diagnostic = RadioFrame{};
            diagnostic.zlf_offset = record.offset;
            diagnostic.datetime_binary = record.datetime_binary;
            diagnostic.session_id = record.session_id;
            diagnostic.diagnostic = true;
            diagnostic.issue = "unframed PTI bytes";
            diagnostic.mpdu.assign(data.begin() + at, data.end());
            out.push_back(std::move(diagnostic));
            break;
        }
        const auto length = static_cast<std::size_t>(le16(data, at + 1)) + 2;
        if (length > data.size() - at || length < 5) {
            auto diagnostic = RadioFrame{};
            diagnostic.zlf_offset = record.offset;
            diagnostic.datetime_binary = record.datetime_binary;
            diagnostic.session_id = record.session_id;
            diagnostic.diagnostic = true;
            diagnostic.issue = "truncated DCH frame";
            diagnostic.mpdu.assign(data.begin() + at, data.end());
            out.push_back(std::move(diagnostic));
            break;
        }
        out.push_back(decode_one(data.subspan(at, length), record));
        at += length;
    }
    return out;
}

} // namespace zw::zniffer
