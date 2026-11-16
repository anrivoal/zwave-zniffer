// SPDX-License-Identifier: BSD-3-Clause
#include "zniffer/xml_commands.hpp"

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <algorithm>
#include <bit>
#include <functional>
#include <memory>
#include <stdexcept>

namespace zw::zniffer {
namespace {

bool tag(const xmlNode* node, const char* name) {
    return node && node->type == XML_ELEMENT_NODE && xmlStrEqual(node->name, BAD_CAST name);
}

std::string attr(const xmlNode* node, const char* name) {
    auto* value = xmlGetProp(node, BAD_CAST name);
    if (!value) return {};
    std::string result(reinterpret_cast<const char*>(value));
    xmlFree(value);
    return result;
}

unsigned number(const std::string& value, unsigned fallback = 0) {
    if (value.empty()) return fallback;
    try { return static_cast<unsigned>(std::stoul(value, nullptr, 0)); }
    catch (...) { return fallback; }
}

int signed_number(const std::string& value) {
    if (value.empty()) return 0;
    try { return std::stoi(value, nullptr, 0); }
    catch (...) { return 0; }
}

std::string hex_bytes(std::span<const std::uint8_t> bytes) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const auto byte : bytes) {
        out.push_back(digits[byte >> 4]);
        out.push_back(digits[byte & 15]);
    }
    return out;
}

std::string display_name(const xmlNode* node) {
    auto help = attr(node, "help");
    return help.empty() ? attr(node, "name") : help;
}

} // namespace

XmlCommands::XmlCommands(const std::string& command_path, const std::string& frame_path) {
    std::unique_ptr<xmlDoc, decltype(&xmlFreeDoc)> document(
        xmlReadFile(command_path.c_str(), nullptr, XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING),
        xmlFreeDoc);
    if (!document) throw std::runtime_error("cannot load Z-Wave XML command definitions");
    const auto* root = xmlDocGetRootElement(document.get());
    if (!root || !tag(root, "zw_classes"))
        throw std::runtime_error("invalid Z-Wave XML command definitions");
    std::function<Parameter(const xmlNode*)> parse_command_param = [&](const xmlNode* field) {
        Parameter param;
        param.group = tag(field, "variant_group");
        param.name = attr(field, "name");
        param.type = attr(field, "type");
        const auto optional = attr(field, "optionaloffs");
        if (!optional.empty()) {
            param.optional_offset = static_cast<int>(number(optional));
            param.optional_mask = number(attr(field, "optionalmask"));
        }
        if (param.group) {
            const auto ref = number(attr(field, "paramOffs"), 255);
            param.size_reference = ref == 255 ? -1 : static_cast<int>(ref);
            param.size_mask = number(attr(field, "sizemask"), 255);
            param.size_change = signed_number(attr(field, "sizechange"));
            const auto more = attr(field, "moretofollowoffs");
            if (!more.empty()) {
                param.more_offset = static_cast<int>(number(more));
                param.more_mask = number(attr(field, "moretofollowmask"));
            }
            for (const auto* child = field->children; child; child = child->next)
                if (tag(child, "param") || tag(child, "variant_group"))
                    param.children.push_back(parse_command_param(child));
            return param;
        }
        if (param.type == "BYTE" || param.type == "CONST" ||
            param.type == "STRUCT_BYTE") param.width = 1;
        else if (param.type == "WORD") param.width = 2;
        else if (param.type == "BIT_24") param.width = 3;
        else if (param.type == "DWORD") param.width = 4;
        for (const auto* child = field->children; child; child = child->next) {
            if (tag(child, "arrayattrib")) param.width = number(attr(child, "len"));
            else if (tag(child, "bitfield") || tag(child, "bitflag")) {
                Bit bit;
                bit.name = attr(child, tag(child, "bitfield") ? "fieldname" : "flagname");
                bit.mask = number(attr(child, tag(child, "bitfield") ? "fieldmask" : "flagmask"));
                const auto shifter = attr(child, "shifter");
                bit.shift = shifter.empty() && bit.mask ? std::countr_zero(bit.mask) :
                    number(shifter);
                if (bit.mask || param.type == "BITMASK") param.bits.push_back(std::move(bit));
            } else if (tag(child, "const")) {
                param.constants[number(attr(child, "key"))] = attr(child, "flagname");
            } else if (tag(child, "variant") || tag(child, "bitmask")) {
                const auto reference = attr(child, "paramoffs");
                if (!reference.empty()) {
                    const auto ref = number(reference);
                    param.size_reference = ref == 255 ? -1 : static_cast<int>(ref);
                    param.size_mask = number(attr(child,
                        tag(child, "variant") ? "sizemask" : "lenmask"), 255);
                }
                const auto fixed = attr(child, "len");
                if (!fixed.empty()) param.width = number(fixed);
                param.size_change = signed_number(attr(child, "sizechange"));
            }
        }
        return param;
    };
    for (const auto* cc = root->children; cc; cc = cc->next) {
        if (!tag(cc, "cmd_class")) continue;
        const auto key = number(attr(cc, "key"), 256);
        const auto version = number(attr(cc, "version"));
        if (key > 255) continue;
        for (const auto* cmd = cc->children; cmd; cmd = cmd->next) {
            if (!tag(cmd, "cmd")) continue;
            const auto command = number(attr(cmd, "key"), 256);
            if (command > 255) continue;
            const auto map_key = static_cast<std::uint16_t>((key << 8) | command);
            auto found = commands_.find(map_key);
            if (found != commands_.end() && found->second.version >= version) continue;
            Definition definition;
            definition.name = display_name(cmd);
            definition.command_class = display_name(cc);
            definition.version = version;
            for (const auto* field = cmd->children; field; field = field->next) {
                if (tag(field, "param") || tag(field, "variant_group"))
                    definition.params.push_back(parse_command_param(field));
            }
            commands_.insert_or_assign(map_key, std::move(definition));
        }
    }
    std::unique_ptr<xmlDoc, decltype(&xmlFreeDoc)> frame_document(
        xmlReadFile(frame_path.c_str(), nullptr, XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING),
        xmlFreeDoc);
    if (!frame_document || !tag(xmlDocGetRootElement(frame_document.get()), "FrameDefinition"))
        throw std::runtime_error("cannot load Z-Wave XML frame definitions");
    std::function<HeaderParam(const xmlNode*)> parse_param = [&](const xmlNode* node) {
        HeaderParam param;
        param.code = attr(node, "Name");
        param.name = attr(node, "Text");
        if (param.name.empty()) param.name = param.code;
        param.bits = number(attr(node, "Bits"));
        param.size_ref = attr(node, "SizeRef");
        param.optional_ref = attr(node, "OptRef");
        for (const auto* child = node->children; child; child = child->next)
            if (tag(child, "Param")) param.children.push_back(parse_param(child));
        return param;
    };
    for (const auto* node = xmlDocGetRootElement(frame_document.get())->children;
         node; node = node->next) {
        if (tag(node, "RadioFrequency")) {
            const auto code = number(attr(node, "Code"), 256);
            const auto layout = number(attr(node, "BaseHeader"), 3);
            if (code < 256 && layout < headers_.size())
                frequency_layouts_[code] = layout;
            continue;
        }
        if (tag(node, "BaseHeader")) {
            const auto key = number(attr(node, "Key"), 3);
            if (key >= headers_.size()) continue;
            for (const auto* child = node->children; child; child = child->next)
                if (tag(child, "Param")) headers_[key].push_back(parse_param(child));
        } else if (tag(node, "Header")) {
            HeaderDefinition header;
            header.key = number(attr(node, "Key"));
            header.layout = number(attr(node, "BaseHeaderKey"), 3);
            header.name = attr(node, "Text");
            if (header.layout >= headers_.size()) continue;
            for (const auto* child = node->children; child; child = child->next) {
                if (tag(child, "Param")) header.params.push_back(parse_param(child));
                else if (tag(child, "Validation"))
                    header.validations.emplace_back(attr(child, "ParamName"),
                                                    number(attr(child, "ParamHexValue")));
            }
            frame_headers_.push_back(std::move(header));
        }
    }
}

unsigned XmlCommands::layout_for_frequency(unsigned code) const {
    const auto found = frequency_layouts_.find(code);
    return found == frequency_layouts_.end() ? 0U : found->second;
}

std::vector<XmlField> XmlCommands::decode_header(std::span<const std::uint8_t> mpdu,
                                                 unsigned layout) const {
    std::vector<XmlField> fields;
    if (layout >= headers_.size()) return fields;
    std::size_t offset = 0;
    std::function<void(const HeaderParam&, std::uint32_t, const std::string&)> add =
        [&](const HeaderParam& param, std::uint32_t value, const std::string& prefix) {
            const auto name = prefix + param.name;
            fields.push_back(XmlField{name, value, {}, {}});
            unsigned bit_offset = 0;
            for (const auto& child : param.children) {
                if (!child.bits || child.bits > 32 || bit_offset + child.bits > param.bits) break;
                const auto mask = child.bits == 32 ? 0xffffffffU : (1U << child.bits) - 1U;
                add(child, (value >> bit_offset) & mask, name + ".");
                bit_offset += child.bits;
            }
        };
    for (const auto& param : headers_[layout]) {
        if (!param.bits || param.bits > 32 || param.bits % 8 != 0) break;
        const auto bytes = param.bits / 8;
        if (offset + bytes > mpdu.size()) break;
        std::uint32_t value = 0;
        for (unsigned i = 0; i < bytes; ++i) value = (value << 8) | mpdu[offset + i];
        offset += bytes;
        add(param, value, {});
    }
    return fields;
}

std::optional<XmlFrame> XmlCommands::decode_frame(std::span<const std::uint8_t> mpdu,
                                                  unsigned layout) const {
    if (layout >= headers_.size()) return std::nullopt;
    using Values = std::unordered_map<std::string, std::uint32_t>;
    auto parse = [&](const std::vector<HeaderParam>& params, std::size_t& offset,
                     Values& values, std::vector<XmlField>& fields) {
        std::function<void(const HeaderParam&, std::uint32_t,
                           const std::string&, const std::string&)> add =
            [&](const HeaderParam& param, std::uint32_t value,
                const std::string& code_prefix, const std::string& name_prefix) {
                const auto code = code_prefix + param.code;
                const auto name = name_prefix + param.name;
                values[code] = value;
                fields.push_back(XmlField{name, value, {}, {}});
                unsigned bit_offset = 0;
                for (const auto& child : param.children) {
                    if (!child.bits || child.bits > 32 || bit_offset + child.bits > param.bits) break;
                    const auto mask = child.bits == 32 ? 0xffffffffU : (1U << child.bits) - 1U;
                    add(child, (value >> bit_offset) & mask, code + ".", name + ".");
                    bit_offset += child.bits;
                }
            };
        for (const auto& param : params) {
            if (!param.optional_ref.empty()) {
                const auto found = values.find(param.optional_ref);
                if (found == values.end() || found->second == 0) continue;
            }
            if (!param.bits || param.bits > 32 || param.bits % 8 != 0) return false;
            std::size_t count = 1;
            if (!param.size_ref.empty()) {
                const auto found = values.find(param.size_ref);
                if (found == values.end()) return false;
                count = found->second;
            }
            const auto bytes = param.bits / 8;
            if (count > (mpdu.size() - std::min(offset, mpdu.size())) / bytes) return false;
            for (std::size_t i = 0; i < count; ++i) {
                std::uint32_t value = 0;
                for (unsigned j = 0; j < bytes; ++j) value = (value << 8) | mpdu[offset + j];
                offset += bytes;
                if (count == 1) add(param, value, {}, {});
                else {
                    HeaderParam item = param;
                    item.code += "[" + std::to_string(i) + "]";
                    item.name += " [" + std::to_string(i + 1) + "]";
                    add(item, value, {}, {});
                }
            }
        }
        return true;
    };
    std::size_t base_bytes = 0;
    Values base_values;
    std::vector<XmlField> base_fields;
    if (!parse(headers_[layout], base_bytes, base_values, base_fields)) return std::nullopt;
    std::optional<XmlFrame> best;
    std::size_t best_rules = 0;
    for (const auto& header : frame_headers_) {
        if (header.layout != layout) continue;
        auto offset = base_bytes;
        auto values = base_values;
        auto fields = base_fields;
        if (!parse(header.params, offset, values, fields)) continue;
        bool match = true;
        for (const auto& [name, expected] : header.validations) {
            const auto found = values.find(name);
            if (found == values.end() || found->second != expected) {
                match = false;
                break;
            }
        }
        if (match && (!best || header.validations.size() > best_rules)) {
            best = XmlFrame{header.name, header.key, offset, std::move(fields)};
            best_rules = header.validations.size();
        }
    }
    return best;
}

std::optional<XmlCommand> XmlCommands::decode(std::span<const std::uint8_t> payload) const {
    if (payload.size() < 2) return std::nullopt;
    const auto found = commands_.find(static_cast<std::uint16_t>((payload[0] << 8) | payload[1]));
    if (found == commands_.end()) return std::nullopt;
    const auto& definition = found->second;
    XmlCommand result{definition.name, definition.command_class, definition.version, {}};
    // These commands contain network keys. Their names can be shown, but no
    // parameter value may leave the native process.
    if ((payload[0] == 0x98 && payload[1] == 0x06) ||
        (payload[0] == 0x9f && payload[1] == 0x0a)) return result;
    std::size_t offset = 2;
    using Values = std::vector<std::uint32_t>;
    auto reference = [](int index, const Values& local, const Values* parent)
        -> std::optional<std::uint32_t> {
        if (index < 0) return std::nullopt;
        const auto n = static_cast<std::size_t>(index);
        if (n >= 128 && parent && n - 128 < parent->size()) return (*parent)[n - 128];
        if (n < local.size()) return local[n];
        return std::nullopt;
    };
    std::function<void(const std::vector<Parameter>&, Values&, const Values*,
                       const std::string&, std::size_t, unsigned)> parse =
        [&](const std::vector<Parameter>& params, Values& values, const Values* parent,
            const std::string& prefix, std::size_t inherited_tail, unsigned depth) {
            if (depth > 4) return;
            for (std::size_t index = 0; index < params.size(); ++index) {
                const auto& param = params[index];
                if (param.optional_offset >= 0) {
                    const auto source = reference(param.optional_offset, values, parent);
                    if (!source || !(*source & param.optional_mask)) {
                        values.push_back(0);
                        continue;
                    }
                }
                std::size_t tail = inherited_tail;
                for (std::size_t next = index + 1; next < params.size(); ++next)
                    if (params[next].optional_offset < 0 && !params[next].group &&
                        params[next].size_reference == -2)
                        tail += params[next].width;
                if (param.group) {
                    unsigned limit = 64;
                    if (param.size_reference >= 0) {
                        const auto source = reference(param.size_reference, values, parent);
                        if (!source) break;
                        const auto count = static_cast<int>(*source & param.size_mask) +
                            param.size_change;
                        limit = count > 0 ? std::min(count, 64) : 0;
                    }
                    unsigned repeats = 0;
                    while (repeats < limit && offset + tail < payload.size()) {
                        const auto before = offset;
                        Values child_values;
                        parse(param.children, child_values, &values,
                              prefix + param.name + "[" + std::to_string(repeats + 1) + "].",
                              tail, depth + 1);
                        if (offset == before) break;
                        ++repeats;
                        if (param.more_offset >= 0) {
                            const auto follow = reference(param.more_offset, child_values, &values);
                            if (!follow || !(*follow & param.more_mask)) break;
                        }
                    }
                    values.push_back(repeats);
                    continue;
                }
                std::size_t width = param.width;
                if (param.size_reference == -1 && width == 0) {
                    width = payload.size() > offset + tail ? payload.size() - offset - tail : 0;
                } else if (param.size_reference >= 0) {
                    const auto source = reference(param.size_reference, values, parent);
                    if (!source) break;
                    const auto length = static_cast<int>(*source & param.size_mask) +
                        param.size_change;
                    width = length > 0 ? static_cast<std::size_t>(length) : 0;
                }
                if (offset + width > payload.size()) break;
                if (param.type == "VARIANT" || param.type == "BITMASK" ||
                    param.type == "ARRAY") {
                    if (width) result.fields.push_back(XmlField{prefix + param.name,
                        static_cast<std::uint32_t>(width), {},
                        hex_bytes(payload.subspan(offset, width))});
                    if (param.type == "BITMASK")
                        for (const auto& bit : param.bits) {
                            const auto at = static_cast<std::size_t>(bit.mask);
                            if (at < width * 8)
                                result.fields.push_back(XmlField{
                                    prefix + param.name + "." + bit.name,
                                    static_cast<std::uint32_t>((payload[offset + at / 8] >> (at % 8)) & 1),
                                    {}, {}});
                        }
                    offset += width;
                    values.push_back(static_cast<std::uint32_t>(width));
                    continue;
                }
                if (width == 0 || width > 4) break;
                std::uint32_t value = 0;
                for (std::size_t i = 0; i < width; ++i)
                    value = (value << 8) | payload[offset + i];
                offset += width;
                values.push_back(value);
                XmlField field{prefix + param.name, value, {}, {}};
                const auto label = param.constants.find(value);
                if (label != param.constants.end()) field.label = label->second;
                result.fields.push_back(std::move(field));
                if (param.type == "STRUCT_BYTE")
                    for (const auto& bit : param.bits)
                        result.fields.push_back(XmlField{prefix + param.name + "." + bit.name,
                            (value & bit.mask) >> bit.shift, {}, {}});
            }
        };
    Values values;
    parse(definition.params, values, nullptr, {}, 0, 0);
    return result;
}

} // namespace zw::zniffer
