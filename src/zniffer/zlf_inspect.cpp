// SPDX-License-Identifier: BSD-3-Clause
#include "zniffer/zlf.hpp"
#include "zniffer/radio.hpp"
#include "zniffer/serial.hpp"

#include <array>
#include <fstream>
#include <iostream>
#include <map>

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: zlf_inspect FILE.zlf\n";
        return 2;
    }
    std::ifstream input(argv[1], std::ios::binary);
    if (!input) {
        std::cerr << "cannot open input\n";
        return 2;
    }
    try {
        zw::zlf::StreamParser parser;
        zw::zniffer::SerialDecoder serial;
        std::array<std::uint8_t, 64 * 1024> buffer{};
        std::map<unsigned, std::size_t> counts;
        std::map<unsigned, std::size_t> attachments;
        std::map<std::string, std::size_t> pti_issues;
        std::size_t pti_frames = 0;
        std::size_t rx_frames = 0;
        std::size_t serial_frames = 0;
        std::size_t total = 0;
        while (input) {
            input.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
            const auto n = input.gcount();
            if (n <= 0) break;
            parser.feed(std::span(buffer.data(), static_cast<std::size_t>(n)));
            for (const auto& record : parser.take_records()) {
                ++counts[record.api_type];
                ++total;
                if (record.has_attachment) ++attachments[record.attachment.type];
                for (const auto& frame : zw::zniffer::decode_pti(record)) {
                    ++pti_frames;
                    if (frame.received) ++rx_frames;
                    if (!frame.issue.empty()) ++pti_issues[frame.issue];
                }
                serial_frames += serial.feed(record).size();
            }
        }
        parser.finish();
        std::cout << "version=" << parser.header().version
                  << " comment=" << parser.header().comment
                  << " records=" << total << '\n';
        for (const auto& [type, count] : counts)
            std::cout << "api=" << type << " (" << zw::zlf::api_type_name(type)
                      << ") count=" << count << '\n';
        for (const auto& [type, count] : attachments)
            std::cout << "attachment=" << type << " count=" << count << '\n';
        std::cout << "pti_frames=" << pti_frames << " rx_frames=" << rx_frames << '\n';
        std::cout << "serial_frames=" << serial_frames << '\n';
        for (const auto& [issue, count] : pti_issues)
            std::cout << "pti_issue=" << issue << " count=" << count << '\n';
    } catch (const zw::zlf::ParseError& error) {
        std::cerr << "ZLF error at byte " << error.offset << ": " << error.what() << '\n';
        return 1;
    }
}
