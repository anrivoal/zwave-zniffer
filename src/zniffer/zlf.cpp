// SPDX-License-Identifier: BSD-3-Clause
#include "zniffer/zlf.hpp"

#include <algorithm>
#include <limits>
#include <utility>

namespace zw::zlf {
namespace {

std::uint16_t u16(std::span<const std::uint8_t> bytes, std::size_t at) {
    return static_cast<std::uint16_t>(bytes[at] | (bytes[at + 1] << 8));
}

std::uint32_t u32(std::span<const std::uint8_t> bytes, std::size_t at) {
    return static_cast<std::uint32_t>(bytes[at]) |
           (static_cast<std::uint32_t>(bytes[at + 1]) << 8) |
           (static_cast<std::uint32_t>(bytes[at + 2]) << 16) |
           (static_cast<std::uint32_t>(bytes[at + 3]) << 24);
}

std::uint32_t u32be(std::span<const std::uint8_t> bytes, std::size_t at) {
    return (static_cast<std::uint32_t>(bytes[at]) << 24) |
           (static_cast<std::uint32_t>(bytes[at + 1]) << 16) |
           (static_cast<std::uint32_t>(bytes[at + 2]) << 8) |
           bytes[at + 3];
}

std::uint64_t u64(std::span<const std::uint8_t> bytes, std::size_t at) {
    return static_cast<std::uint64_t>(u32(bytes, at)) |
           (static_cast<std::uint64_t>(u32(bytes, at + 4)) << 32);
}

void append_utf8(std::string& out, std::uint32_t point) {
    if (point <= 0x7f) out.push_back(static_cast<char>(point));
    else if (point <= 0x7ff) {
        out.push_back(static_cast<char>(0xc0 | (point >> 6)));
        out.push_back(static_cast<char>(0x80 | (point & 0x3f)));
    } else if (point <= 0xffff) {
        out.push_back(static_cast<char>(0xe0 | (point >> 12)));
        out.push_back(static_cast<char>(0x80 | ((point >> 6) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | (point & 0x3f)));
    } else {
        out.push_back(static_cast<char>(0xf0 | (point >> 18)));
        out.push_back(static_cast<char>(0x80 | ((point >> 12) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | ((point >> 6) & 0x3f)));
        out.push_back(static_cast<char>(0x80 | (point & 0x3f)));
    }
}

std::string utf16le(std::span<const std::uint8_t> bytes) {
    std::string out;
    for (std::size_t at = 0; at + 1 < bytes.size(); at += 2) {
        std::uint32_t point = u16(bytes, at);
        if (point == 0) break;
        if (point >= 0xd800 && point <= 0xdbff && at + 3 < bytes.size()) {
            auto low = u16(bytes, at + 2);
            if (low >= 0xdc00 && low <= 0xdfff) {
                point = static_cast<std::uint32_t>(0x10000 + ((point - 0xd800) << 10) + low - 0xdc00);
                at += 2;
            } else point = 0xfffd;
        } else if (point >= 0xd800 && point <= 0xdfff) point = 0xfffd;
        append_utf8(out, point);
    }
    return out;
}

std::vector<std::uint16_t> utf8_to_utf16(std::string_view utf8) {
    std::vector<std::uint16_t> out;
    for (std::size_t i = 0; i < utf8.size();) {
        const auto first = static_cast<std::uint8_t>(utf8[i]);
        std::uint32_t point = 0;
        std::size_t count = 0;
        if (first < 0x80) { point = first; count = 1; }
        else if ((first & 0xe0) == 0xc0) { point = first & 0x1f; count = 2; }
        else if ((first & 0xf0) == 0xe0) { point = first & 0x0f; count = 3; }
        else if ((first & 0xf8) == 0xf0) { point = first & 0x07; count = 4; }
        else throw std::invalid_argument("invalid UTF-8 trace comment");
        if (i + count > utf8.size()) throw std::invalid_argument("truncated UTF-8 trace comment");
        for (std::size_t j = 1; j < count; ++j) {
            const auto c = static_cast<std::uint8_t>(utf8[i + j]);
            if ((c & 0xc0) != 0x80) throw std::invalid_argument("invalid UTF-8 trace comment");
            point = (point << 6) | (c & 0x3f);
        }
        if ((count == 2 && point < 0x80) || (count == 3 && point < 0x800) ||
            (count == 4 && point < 0x10000) || point > 0x10ffff ||
            (point >= 0xd800 && point <= 0xdfff))
            throw std::invalid_argument("invalid Unicode trace comment");
        if (point <= 0xffff) out.push_back(static_cast<std::uint16_t>(point));
        else {
            point -= 0x10000;
            out.push_back(static_cast<std::uint16_t>(0xd800 + (point >> 10)));
            out.push_back(static_cast<std::uint16_t>(0xdc00 + (point & 0x3ff)));
        }
        i += count;
    }
    return out;
}

Attachment parse_attachment(std::span<const std::uint8_t> data, std::uint64_t offset) {
    if (data.size() < 2) throw ParseError(offset, "attachment has no type/version");
    Attachment a;
    a.type = data[0];
    a.version = data[1];
    a.body.assign(data.begin() + 2, data.end());
    const auto body = std::span<const std::uint8_t>(a.body);
    if (a.version != 1) return a; // Preserve future versions byte-for-byte.
    if (a.type == static_cast<std::uint8_t>(AttachmentType::session)) {
        // C# SessionAttachment: reserved, API, reserved, session ID,
        // ASCII name length/name, ASCII args length/args.
        if (body.size() < 6) throw ParseError(offset, "truncated session attachment");
        a.session_api_type = body[1];
        a.session_id = body[3];
        std::size_t at = 4;
        const auto name_length = body[at++];
        if (at + name_length + 1 > body.size()) throw ParseError(offset, "truncated session name");
        a.session_name.assign(body.begin() + at, body.begin() + at + name_length);
        at += name_length;
        const auto args_length = body[at++];
        if (at + args_length > body.size()) throw ParseError(offset, "truncated session args");
        a.session_args.assign(body.begin() + at, body.begin() + at + args_length);
    } else if (a.type == static_cast<std::uint8_t>(AttachmentType::network_keys)) {
        // Parse embedded keys for the native security layer; never send them to the UI.
        std::size_t at = 0;
        while (at < body.size()) {
            if (body.size() - at < 6) throw ParseError(offset, "truncated key group");
            Attachment::NetworkKeyGroup group;
            group.home_id = u32be(body, at);
            at += 4;
            const auto count = body[at++];
            group.temporary = (body[at++] & 1) != 0;
            if (body.size() - at < static_cast<std::size_t>(count) * 16)
                throw ParseError(offset, "truncated network keys");
            group.keys.reserve(count);
            for (std::size_t i = 0; i < count; ++i) {
                std::array<std::uint8_t, 16> key{};
                std::copy_n(body.begin() + at, 16, key.begin());
                group.keys.push_back(key);
                at += 16;
            }
            (group.temporary ? a.temporary_key_count : a.network_key_count) += count;
            a.network_key_groups.push_back(std::move(group));
        }
    }
    // The C# FrameCommentAttachment parser/serializer are placeholders.
    // Its full body stays opaque until an actual annotated trace defines it.
    return a;
}

} // namespace

ParseError::ParseError(std::uint64_t at, const std::string& message)
    : std::runtime_error(message), offset(at) {}

std::uint16_t header_crc(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < header_size) throw ParseError(0, "ZLF header is incomplete");
    std::uint16_t crc = 0xffff;
    for (std::size_t i = 0; i < header_size - 2; ++i) {
        for (int bit = 7; bit >= 0; --bit) {
            const bool carry = (crc & 0x8000) != 0;
            crc = static_cast<std::uint16_t>((crc << 1) | ((bytes[i] >> bit) & 1));
            if (carry) crc ^= 0x1021;
        }
    }
    for (int bit = 0; bit < 16; ++bit) {
        const bool carry = (crc & 0x8000) != 0;
        crc = static_cast<std::uint16_t>(crc << 1);
        if (carry) crc ^= 0x1021;
    }
    return crc;
}

Header parse_header(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < header_size) throw ParseError(0, "ZLF header is incomplete");
    Header result;
    result.crc = u16(bytes, header_size - 2);
    if (result.crc != header_crc(bytes)) throw ParseError(2046, "ZLF header CRC mismatch");
    result.version = u32(bytes, 0);
    if (result.version < 100 || result.version > 104)
        throw ParseError(0, "unsupported ZLF header version");
    result.text_encoding = u32(bytes, 4);
    result.comment = utf16le(bytes.subspan(8, 512));
    std::copy_n(bytes.begin(), header_size, result.raw.begin());
    return result;
}

std::array<std::uint8_t, header_size> header_with_comment(const Header& header,
                                                          std::string_view utf8_comment) {
    auto result = header.raw;
    std::fill(result.begin() + 8, result.begin() + 520, 0);
    const auto units = utf8_to_utf16(utf8_comment);
    std::size_t at = 0;
    for (std::size_t i = 0; i < units.size() && at < 254; ++i) {
        if (units[i] >= 0xd800 && units[i] <= 0xdbff && at == 253) break;
        result[8 + at * 2] = static_cast<std::uint8_t>(units[i] & 0xff);
        result[9 + at * 2] = static_cast<std::uint8_t>(units[i] >> 8);
        ++at;
    }
    const auto crc = header_crc(result);
    result[2046] = static_cast<std::uint8_t>(crc);
    result[2047] = static_cast<std::uint8_t>(crc >> 8);
    return result;
}

std::vector<std::uint8_t> serialize_record(const Record& record) {
    if (record.data.size() > std::numeric_limits<std::uint32_t>::max())
        throw std::invalid_argument("ZLF record payload is too large");
    std::vector<std::uint8_t> out(record_overhead + record.data.size());
    for (int i = 0; i < 8; ++i)
        out[i] = static_cast<std::uint8_t>(record.datetime_binary >> (i * 8));
    out[8] = static_cast<std::uint8_t>(record.session_id & 0x7f);
    if (record.outgoing) out[8] |= 0x80;
    const auto length = static_cast<std::uint32_t>(record.data.size());
    for (int i = 0; i < 4; ++i)
        out[9 + i] = static_cast<std::uint8_t>(length >> (i * 8));
    std::copy(record.data.begin(), record.data.end(), out.begin() + 13);
    out.back() = record.eod;
    return out;
}

Record parse_record(std::span<const std::uint8_t> bytes, std::uint64_t offset) {
    if (bytes.size() < record_overhead) throw ParseError(offset, "incomplete ZLF record");
    const auto length = u32(bytes, 9);
    if (length > bytes.size() - record_overhead)
        throw ParseError(offset, "truncated ZLF record payload");
    Record r;
    r.offset = offset;
    r.datetime_binary = u64(bytes, 0);
    r.outgoing = (bytes[8] & 0x80) != 0;
    r.session_id = bytes[8] & 0x7f;
    r.data.assign(bytes.begin() + 13, bytes.begin() + 13 + length);
    r.eod = bytes[13 + length];
    r.api_type = static_cast<std::uint8_t>(0xfe - r.eod);
    r.has_attachment = r.api_type == static_cast<std::uint8_t>(ApiType::attachment);
    if (r.has_attachment) r.attachment = parse_attachment(r.data, offset + 13);
    return r;
}

std::string api_type_name(std::uint8_t type) {
    switch (type) {
        case 0: return "Zniffer serial";
        case 1: return "Serial API";
        case 2: return "Programmer";
        case 3: return "ZIP";
        case 4: return "Reserved 4";
        case 5: return "Reserved 5";
        case 6: return "Attachment";
        case 7: return "Text";
        case 8: return "XModem";
        case 9: return "PTI";
        case 10: return "PTI diagnostic";
        case 11: return "UIC";
        case 0x80: return "WSTK instrument";
        case 0x81: return "Rudat attenuator";
        case 0x82: return "E364x power supply";
        case 0x83: return "DMM7510 multimeter";
        case 0x84: return "Sample CLI";
        default: return "Other";
    }
}

StreamParser::StreamParser(std::size_t max_record_bytes)
    : max_record_bytes_(max_record_bytes) {
    if (max_record_bytes < record_overhead)
        throw std::invalid_argument("record limit is too small");
}

void StreamParser::feed(std::span<const std::uint8_t> bytes) {
    if (bytes.size() > std::numeric_limits<std::size_t>::max() - pending_.size())
        throw ParseError(offset_, "input size overflow");
    pending_.insert(pending_.end(), bytes.begin(), bytes.end());
    std::size_t consumed = 0;
    if (!has_header_) {
        if (pending_.size() < header_size) return;
        header_ = parse_header(pending_);
        has_header_ = true;
        consumed = header_size;
    }
    while (pending_.size() - consumed >= record_overhead) {
        const auto length = u32(std::span<const std::uint8_t>(pending_).subspan(consumed), 9);
        if (length > max_record_bytes_ - record_overhead)
            throw ParseError(offset_ + consumed, "ZLF record exceeds configured limit");
        const auto total = static_cast<std::size_t>(length) + record_overhead;
        if (pending_.size() - consumed < total) break;
        ready_.push_back(parse_record(
            std::span<const std::uint8_t>(pending_).subspan(consumed, total), offset_ + consumed));
        consumed += total;
    }
    if (consumed) {
        pending_.erase(pending_.begin(), pending_.begin() + consumed);
        offset_ += consumed;
    }
    if (pending_.size() > max_record_bytes_)
        throw ParseError(offset_, "unbounded partial ZLF record");
}

std::vector<Record> StreamParser::take_records() {
    auto out = std::move(ready_);
    ready_.clear();
    return out;
}

const Header& StreamParser::header() const {
    if (!has_header_) throw std::logic_error("ZLF header is not available yet");
    return header_;
}

bool StreamParser::has_header() const noexcept { return has_header_; }
std::uint64_t StreamParser::next_offset() const noexcept { return offset_ + pending_.size(); }

void StreamParser::finish() const {
    if (!has_header_) throw ParseError(0, "ZLF header is incomplete");
    if (!pending_.empty()) throw ParseError(offset_, "truncated final ZLF record");
}

} // namespace zw::zlf
