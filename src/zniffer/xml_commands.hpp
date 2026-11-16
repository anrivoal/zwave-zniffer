// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include <cstdint>
#include <array>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace zw::zniffer {

struct XmlField {
    std::string name;
    std::uint32_t value{};
    std::string label;
    std::string hex;
};

struct XmlCommand {
    std::string name;
    std::string command_class;
    unsigned version{};
    std::vector<XmlField> fields;
};

struct XmlFrame {
    std::string name;
    unsigned definition_key{};
    std::size_t header_bytes{};
    std::vector<XmlField> fields;
};

class XmlCommands {
public:
    XmlCommands(const std::string& command_path, const std::string& frame_path);
    std::optional<XmlCommand> decode(std::span<const std::uint8_t> payload) const;
    std::vector<XmlField> decode_header(std::span<const std::uint8_t> mpdu,
                                        unsigned layout) const;
    std::optional<XmlFrame> decode_frame(std::span<const std::uint8_t> mpdu,
                                         unsigned layout) const;
    unsigned layout_for_frequency(unsigned code) const;
    std::size_t command_count() const { return commands_.size(); }

private:
    struct Bit {
        std::string name;
        std::uint32_t mask{};
        unsigned shift{};
    };
    struct Parameter {
        std::string name;
        std::string type;
        std::size_t width{};
        bool group{};
        std::vector<Parameter> children;
        std::vector<Bit> bits;
        std::unordered_map<std::uint32_t, std::string> constants;
        int optional_offset{-1};
        std::uint32_t optional_mask{};
        int size_reference{-2}; // -1 means remaining message bytes.
        std::uint32_t size_mask{0xff};
        int size_change{};
        int more_offset{-1};
        std::uint32_t more_mask{};
    };
    struct Definition {
        std::string name;
        std::string command_class;
        unsigned version{};
        std::vector<Parameter> params;
    };
    struct HeaderParam {
        std::string code;
        std::string name;
        unsigned bits{};
        std::string size_ref;
        std::string optional_ref;
        std::vector<HeaderParam> children;
    };
    struct HeaderDefinition {
        std::string name;
        unsigned key{};
        unsigned layout{};
        std::vector<HeaderParam> params;
        std::vector<std::pair<std::string, std::uint32_t>> validations;
    };
    std::unordered_map<std::uint16_t, Definition> commands_;
    std::array<std::vector<HeaderParam>, 3> headers_;
    std::vector<HeaderDefinition> frame_headers_;
    std::unordered_map<unsigned, unsigned> frequency_layouts_;
};

} // namespace zw::zniffer
