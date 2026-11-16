// SPDX-License-Identifier: BSD-3-Clause
#include "zniffer/zlf.hpp"
#include "zniffer/serial.hpp"
#include "zniffer/radio.hpp"
#include "zniffer/mpdu.hpp"
#include "zniffer/s0.hpp"
#include "zniffer/xml_commands.hpp"
#include "zniffer/basic_serial.hpp"

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <vector>

using zw::zlf::StreamParser;

static std::vector<std::uint8_t> header() {
    std::vector<std::uint8_t> b(2048);
    b[0] = 104;
    b[8] = 'T';
    b[10] = 'e';
    b[12] = 's';
    b[14] = 't';
    const auto crc = zw::zlf::header_crc(b);
    b[2046] = crc & 0xff;
    b[2047] = crc >> 8;
    return b;
}

static void append_record(std::vector<std::uint8_t>& b, std::uint8_t type,
                          const std::vector<std::uint8_t>& data) {
    const std::uint64_t ticks = 0x88dc001122334455ULL;
    for (int i = 0; i < 8; ++i) b.push_back((ticks >> (i * 8)) & 0xff);
    b.push_back(0x81); // outgoing, session 1
    const auto len = static_cast<std::uint32_t>(data.size());
    for (int i = 0; i < 4; ++i) b.push_back((len >> (i * 8)) & 0xff);
    b.insert(b.end(), data.begin(), data.end());
    b.push_back(static_cast<std::uint8_t>(0xfe - type));
}

int main() {
    auto b = header();
    append_record(b, 0, {0x21, 0x03, 0x44}); // serial Zniffer raw bytes
    append_record(b, 9, {0x5b, 0x02, 0x00, 0x5d}); // PTI DCH raw bytes
    append_record(b, 6, {5, 1, 0, 9, 0, 3, 3, 'C', 'O', 'M', 1, 'x'});
    append_record(b, 6, {4, 1, 1, 2, 3}); // unknown frame-comment body preserved
    StreamParser parser;
    std::size_t count = 0;
    for (std::size_t at = 0; at < b.size(); at += 7) {
        const auto n = std::min<std::size_t>(7, b.size() - at);
        parser.feed(std::span<const std::uint8_t>(b.data() + at, n));
        for (auto& r : parser.take_records()) {
            if (count == 0) assert(r.api_type == 0 && r.outgoing && r.session_id == 1);
            if (count == 1) assert(r.api_type == 9 && r.data[0] == 0x5b);
            if (count == 2) {
                assert(r.has_attachment && r.attachment.type == 5);
                assert(r.attachment.session_name == "COM");
                assert(r.attachment.session_args == "x");
            }
            if (count == 3) assert(r.attachment.body.size() == 3);
            ++count;
        }
    }
    parser.finish();
    assert(parser.header().version == 104 && parser.header().comment == "Test");
    assert(count == 4);
    const auto rewritten = zw::zlf::header_with_comment(parser.header(), "Test é 🔐");
    assert(zw::zlf::parse_header(rewritten).comment == "Test é 🔐");
    const auto unchanged = zw::zlf::header_with_comment(parser.header(), "Test");
    assert(std::equal(unchanged.begin(), unchanged.end(), b.begin()));
    const auto first_record = zw::zlf::parse_record(std::span(b).subspan(2048), 2048);
    const auto serialized = zw::zlf::serialize_record(first_record);
    assert(std::equal(serialized.begin(), serialized.end(), b.begin() + 2048));
    b[42] ^= 1;
    bool rejected = false;
    try { zw::zlf::parse_header(b); }
    catch (const zw::zlf::ParseError&) { rejected = true; }
    assert(rejected);

    zw::zniffer::SerialDecoder serial;
    zw::zlf::Record serial_record;
    serial_record.api_type = 0;
    serial_record.session_id = 3;
    serial_record.data = {0x21, 0x01, 0, 1, 0x22, 2, 0x9a, 0x21, 0x03, 3, 0x11};
    assert(serial.feed(serial_record).empty());
    serial_record.data = {0x22, 0x33};
    auto frames = serial.feed(serial_record);
    assert(frames.size() == 1 && frames[0].api_version == 4);
    assert(frames[0].channel == 1 && frames[0].speed == 2);
    assert((frames[0].payload == std::vector<std::uint8_t>{0x11, 0x22, 0x33}));
    serial_record.data = {0x3b, 0, 2, 0x23, 1, 0x2c, 0xaa, 0x2c, 0xbb, 0x2e};
    frames = serial.feed(serial_record);
    assert(frames.size() == 1 && frames[0].api_version == 3);
    assert((frames[0].payload == std::vector<std::uint8_t>{0xaa, 0xbb}));

    zw::zniffer::BasicSerialDecoder basic;
    zw::zlf::Record basic_record;
    basic_record.api_type = 1;
    basic_record.session_id = 3;
    basic_record.data = {0x01, 0x03};
    assert(basic.feed(basic_record).empty());
    basic_record.data = {0x00, 0x15, 0xe9, 0x06};
    const auto basic_frames = basic.feed(basic_record);
    assert(basic_frames.size() == 2);
    assert(basic_frames[0].function == 0x15 && basic_frames[0].checksum_ok == true);
    assert(basic_frames[1].marker == 0x06);

    // v3 DCH envelope, TX PTI marker, one region byte, Z-Wave protocol.
    zw::zlf::Record pti_record;
    pti_record.api_type = 9;
    pti_record.data = {
        0x5b, 0x27, 0x00, 0x03, 0x00, 0xac, 0xa4, 0xb0, 0xaa,
        0x74, 0x02, 0x00, 0x00, 0x29, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x78, 0x2f, 0xfc, 0xfe, 0x95, 0x1a, 0x3c, 0x00,
        0x01, 0x01, 0x0d, 0x00, 0x9f, 0x07, 0x01, 0x26, 0xfd,
        0x02, 0x02, 0x06, 0x09, 0x5d
    };
    const auto pti_frames = zw::zniffer::decode_pti(pti_record);
    assert(pti_frames.size() == 1 && pti_frames[0].issue.empty());
    assert(!pti_frames[0].received && pti_frames[0].dch_version == 3);
    assert(pti_frames[0].region == 2 && pti_frames[0].channel == 2);
    assert(pti_frames[0].mpdu.size() == 13);

    zw::zlf::Record pti_v2;
    pti_v2.api_type = 9;
    pti_v2.data = {
        0x5b, 0x1c, 0x00, // DCH length includes its two-byte length field
        0x02, 0x00, 0, 0, 0, 0, 0, 0, 0x2a, 0x00, 1,
        0xf8, 1, 2, 3, 4, 5, 6, 7, 8, 0xf9,
        0xc4, 2, 1, 6, 0x51, 0x5d
    };
    const auto decoded_v2 = zw::zniffer::decode_pti(pti_v2);
    assert(decoded_v2.size() == 1 && decoded_v2[0].issue.empty());
    assert(decoded_v2[0].received && decoded_v2[0].dch_version == 2);
    assert(decoded_v2[0].rssi_dbm == -110);
    assert(decoded_v2[0].mpdu.size() == 8);

    zw::zlf::Record annotation;
    annotation.api_type = 6;
    annotation.data = {3, 1, 0x12, 0x34, 0x56, 0x78, 1, 0};
    annotation.data.insert(annotation.data.end(), 16, 0x42);
    annotation.data.insert(annotation.data.end(), {0, 0, 0, 0, 0, 1});
    auto encoded = header();
    append_record(encoded, 6, annotation.data);
    auto parsed = zw::zlf::parse_record(std::span(encoded).subspan(2048), 2048);
    assert(parsed.has_attachment && parsed.attachment.network_key_count == 1);
    assert(parsed.attachment.temporary_key_count == 0);
    assert(parsed.attachment.network_key_groups.size() == 2);
    assert(parsed.attachment.network_key_groups[0].home_id == 0x12345678);
    assert(!parsed.attachment.network_key_groups[0].temporary);
    assert(parsed.attachment.network_key_groups[0].keys.size() == 1);
    assert(parsed.attachment.network_key_groups[0].keys[0][0] == 0x42);
    assert(parsed.attachment.network_key_groups[1].temporary);
    assert(parsed.attachment.network_key_groups[1].keys.empty());

    zw::zniffer::RadioFrame classic;
    classic.region = 2;
    classic.channel = 0;
    classic.protocol = 6;
    classic.mpdu = {0x12, 0x34, 0x56, 0x78, 7, 0x41, 0x03, 11, 8, 0x20, 0x01};
    auto summary = zw::zniffer::summarize_mpdu(classic);
    assert(summary && summary->home_id == 0x12345678 && summary->source_node == 7);
    assert(summary->destination_node == 8 && summary->sequence == 3);
    assert(summary->ack_requested && summary->type_name == "Singlecast");

    zw::zniffer::RadioFrame long_range;
    long_range.region = 12;
    long_range.channel = 3;
    long_range.protocol = 6;
    long_range.mpdu = {0x12, 0x34, 0x56, 0x78, 0x01, 0x23, 0x45, 0, 0x81, 9, 0, 3};
    summary = zw::zniffer::summarize_mpdu(long_range);
    assert(summary && summary->long_range && summary->source_node == 0x12);
    assert(summary->destination_node == 0x345 && summary->sequence == 9);

    // Public synthetic S0 vector, independently generated with AES-ECB/CBC/OFB.
    zw::zlf::Attachment s0_keys;
    s0_keys.type = 3;
    zw::zlf::Attachment::NetworkKeyGroup s0_group;
    s0_group.home_id = 0x12345678;
    std::array<std::uint8_t, 16> s0_key{};
    for (std::size_t i = 0; i < 16; ++i) s0_key[i] = static_cast<std::uint8_t>(i + 1);
    s0_group.keys.push_back(s0_key);
    s0_keys.network_key_groups.push_back(s0_group);
    zw::zniffer::S0Decoder s0;
    s0.add_keys(s0_keys);
    zw::zniffer::RadioFrame nonce_frame;
    nonce_frame.region = 2;
    nonce_frame.channel = 0;
    nonce_frame.protocol = 6;
    nonce_frame.mpdu = {0x12,0x34,0x56,0x78,0x01,0x41,0x00,0x15,0x02,
                        0x98,0x80,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0,0};
    assert(s0.process(nonce_frame).is_s0);
    zw::zniffer::RadioFrame encrypted_frame = nonce_frame;
    encrypted_frame.mpdu = {0x12,0x34,0x56,0x78,0x02,0x41,0x00,0x21,0x01,
                            0x98,0x81,0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,
                            0xb8,0xd0,0xe2,0x11,0xa7,0x4f,0xdd,0xb8,0x85,
                            0x36,0xbe,0x9d,0,0};
    auto s0_result = s0.process(encrypted_frame);
    assert(s0_result.encrypted && s0_result.decrypted);
    assert((s0_result.plaintext == std::vector<std::uint8_t>{0x20, 0x02}));
    encrypted_frame.mpdu[28] ^= 1; // Invalid authentication tag.
    const auto s0_bad = s0.process(encrypted_frame);
    assert(s0_bad.encrypted && !s0_bad.decrypted);

    zw::zniffer::XmlCommands xml(ZW_XML_ROOT "/ZWave_cmd_classes.xml",
                                 ZW_XML_ROOT "/FrameDefinition.xml");
    assert(xml.command_count() > 500);
    const std::array<std::uint8_t, 3> basic_set{0x20, 0x01, 0x42};
    const auto command = xml.decode(basic_set);
    assert(command && command->name == "Basic Set");
    assert(command->fields.size() == 1 && command->fields[0].value == 0x42);
    const std::array<std::uint8_t, 18> hidden_key{0x98, 0x06};
    const auto key_command = xml.decode(hidden_key);
    assert(key_command && key_command->fields.empty());
    const std::array<std::uint8_t, 6> kex_report{0x9f,0x05,0x00,0x02,0x01,0x87};
    const auto kex = xml.decode(kex_report);
    assert(kex);
    const auto s0_bit = std::find_if(kex->fields.begin(), kex->fields.end(),
        [](const auto& field) { return field.name == "Requested Keys.S0"; });
    assert(s0_bit != kex->fields.end() && s0_bit->value == 1);
    const std::array<std::uint8_t, 9> frame_header{0x12,0x34,0x56,0x78,0x01,0x41,0x02,0x0d,0x02};
    const auto header_fields = xml.decode_header(frame_header, 0);
    const auto source = std::find_if(header_fields.begin(), header_fields.end(),
        [](const auto& field) { return field.name == "Source Node ID"; });
    assert(source != header_fields.end() && source->value == 1);
    const auto described = xml.decode_frame(frame_header, 0);
    assert(described && described->name == "Singlecast" && described->header_bytes == 9);
}
