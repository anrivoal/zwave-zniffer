// SPDX-License-Identifier: BSD-3-Clause
// ZLF layout follows Silicon Labs' z-wave-tools-core StorageHeader/DataChunk.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace zw::zlf {

constexpr std::size_t header_size = 2048;
constexpr std::size_t record_overhead = 14;

enum class ApiType : std::uint8_t {
    zniffer = 0x00,
    basic = 0x01,
    programmer = 0x02,
    zip = 0x03,
    attachment = 0x06,
    text = 0x07,
    xmodem = 0x08,
    pti = 0x09,
    pti_diagnostic = 0x0a,
    uic = 0x0b,
    wstk_instrument = 0x80,
    attenuator = 0x81,
    power_supply = 0x82,
    multimeter = 0x83,
    sample_cli = 0x84,
};

enum class AttachmentType : std::uint8_t {
    indexes = 0x01,
    filters = 0x02,
    network_keys = 0x03,
    frame_comment = 0x04,
    session = 0x05,
};

struct Header {
    std::uint32_t version{};
    std::uint32_t text_encoding{};
    std::string comment;
    std::uint16_t crc{};
    std::array<std::uint8_t, header_size> raw{};
};

struct Attachment {
    struct NetworkKeyGroup {
        std::uint32_t home_id{};
        bool temporary{};
        std::vector<std::array<std::uint8_t, 16>> keys;
    };
    std::uint8_t type{};
    std::uint8_t version{};
    std::vector<std::uint8_t> body;
    // Decoded only for known, documented structures; body is always preserved.
    std::string session_name;
    std::string session_args;
    std::uint8_t session_api_type{};
    std::uint8_t session_id{};
    std::size_t network_key_count{};
    std::size_t temporary_key_count{};
    std::vector<NetworkKeyGroup> network_key_groups;
};

struct Record {
    std::uint64_t offset{};
    std::uint64_t datetime_binary{};
    bool outgoing{};
    std::uint8_t session_id{};
    std::uint8_t eod{};
    std::uint8_t api_type{};
    std::vector<std::uint8_t> data;
    Attachment attachment;
    bool has_attachment{};
};

struct ParseError : std::runtime_error {
    std::uint64_t offset;
    ParseError(std::uint64_t at, const std::string& message);
};

Header parse_header(std::span<const std::uint8_t> bytes);
Record parse_record(std::span<const std::uint8_t> bytes, std::uint64_t offset);
std::uint16_t header_crc(std::span<const std::uint8_t> bytes);
std::array<std::uint8_t, header_size> header_with_comment(const Header& header,
                                                          std::string_view utf8_comment);
std::vector<std::uint8_t> serialize_record(const Record& record);
std::string api_type_name(std::uint8_t type);

// Incremental parser: callers provide bounded browser File.slice() ranges.
// No source file is written to or opened by the service.
class StreamParser {
public:
    explicit StreamParser(std::size_t max_record_bytes = 16 * 1024 * 1024);
    void feed(std::span<const std::uint8_t> bytes);
    std::vector<Record> take_records();
    const Header& header() const;
    bool has_header() const noexcept;
    std::uint64_t next_offset() const noexcept;
    void finish() const;

private:
    std::vector<std::uint8_t> pending_;
    std::vector<Record> ready_;
    Header header_;
    std::uint64_t offset_{};
    std::size_t max_record_bytes_;
    bool has_header_{};
};

} // namespace zw::zlf
