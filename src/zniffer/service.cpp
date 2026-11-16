// SPDX-License-Identifier: BSD-3-Clause
#include "zniffer/capture.hpp"
#include "zniffer/basic_serial.hpp"
#include "zniffer/mpdu.hpp"
#include "zniffer/radio.hpp"
#include "zniffer/s0.hpp"
#include "zniffer/serial.hpp"
#include "zniffer/s2.hpp"
#include "zniffer/zlf.hpp"
#include "zniffer/xml_commands.hpp"

#include <event2/buffer.h>
#include <event2/event.h>
#include <event2/http.h>
#include <event2/keyvalq_struct.h>

#include <array>
#include <csignal>
#include <charconv>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <unordered_map>

namespace {

struct Session {
    zw::zlf::StreamParser parser;
    zw::zniffer::SerialDecoder serial;
    zw::zniffer::BasicSerialDecoder basic;
    zw::zniffer::S2Decoder s2;
    zw::zniffer::S0Decoder s0;
    std::unique_ptr<zw::zniffer::TcpPtiCapture> capture;
    std::unique_ptr<zw::zniffer::SerialCapture> serial_capture;
    std::size_t records{};
    std::size_t frames{};
    std::size_t basic_frames{};
    std::size_t s2_encrypted{};
    std::size_t s2_decrypted{};
    std::size_t s0_encrypted{};
    std::size_t s0_decrypted{};
    bool replaying{};
};

struct State {
    std::unordered_map<std::string, std::unique_ptr<Session>> sessions;
    std::filesystem::path web_root;
    std::unique_ptr<zw::zniffer::XmlCommands> xml_commands;
};

std::string json_string(std::string_view s) {
    std::string out = "\"";
    static constexpr char hex[] = "0123456789abcdef";
    for (unsigned char c : s) {
        if (c == '"' || c == '\\') { out.push_back('\\'); out.push_back(c); }
        else if (c == '\n') out += "\\n";
        else if (c == '\r') out += "\\r";
        else if (c == '\t') out += "\\t";
        else if (c < 0x20) {
            out += "\\u00";
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 15]);
        } else out.push_back(static_cast<char>(c));
    }
    out.push_back('"');
    return out;
}

std::string to_hex(std::span<const std::uint8_t> bytes) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (auto b : bytes) {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 15]);
    }
    return out;
}

std::string home_id_hex(std::uint32_t value) {
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string result(8, '0');
    for (int i = 7; i >= 0; --i) {
        result[i] = hex[value & 15];
        value >>= 4;
    }
    return result;
}

std::string decrypted_name(std::span<const std::uint8_t> bytes) {
    if (bytes.size() < 2) return "Decrypted command";
    if (bytes[0] == 0x9f) {
        switch (bytes[1]) {
            case 1: return "S2 Nonce Get";
            case 2: return "S2 Nonce Report";
            case 3: return "S2 Message Encapsulation";
            case 4: return "S2 KEX Get";
            case 5: return "S2 KEX Report";
            case 6: return "S2 KEX Set";
            case 7: return "S2 KEX Fail";
            case 8: return "S2 Public Key Report";
            case 9: return "S2 Network Key Get";
            case 10: return "S2 Network Key Report";
            case 11: return "S2 Network Key Verify";
            case 12: return "S2 Transfer End";
            case 13: return "S2 Commands Supported Get";
            case 14: return "S2 Commands Supported Report";
        }
    }
    if (bytes[0] == 0x8e) return "Multi Channel Association command";
    if (bytes[0] == 0x98) {
        switch (bytes[1]) {
            case 2: return "S0 Commands Supported Get";
            case 3: return "S0 Commands Supported Report";
            case 4: return "S0 Scheme Get";
            case 5: return "S0 Scheme Report";
            case 6: return "S0 Network Key Set";
            case 7: return "S0 Network Key Verify";
            case 8: return "S0 Scheme Inherit";
            case 0x40: return "S0 Nonce Get";
            case 0x80: return "S0 Nonce Report";
            case 0x81: return "S0 Command Encapsulation";
            case 0xc1: return "S0 Command Encapsulation + Nonce Get";
        }
    }
    return "Decrypted command";
}

void append_xml_command(std::ostringstream& out, const zw::zniffer::XmlCommands* xml,
                        std::span<const std::uint8_t> payload, bool decrypted) {
    if (!xml) return;
    const auto command = xml->decode(payload);
    if (!command) return;
    if (decrypted) out << ",\"decryptedName\":" << json_string(command->name);
    else out << ",\"commandName\":" << json_string(command->name);
    out << (decrypted ? ",\"decryptedCommandClass\":" : ",\"commandClass\":")
        << json_string(command->command_class)
        << (decrypted ? ",\"decryptedCommandVersion\":" : ",\"commandVersion\":")
        << command->version;
    if (!command->fields.empty()) {
        out << (decrypted ? ",\"decryptedFields\":[" : ",\"commandFields\":[");
        bool first = true;
        for (const auto& field : command->fields) {
            if (!first) out << ',';
            first = false;
            out << "{\"name\":" << json_string(field.name)
                << ",\"value\":" << field.value;
            if (!field.label.empty()) out << ",\"label\":" << json_string(field.label);
            if (!field.hex.empty()) out << ",\"hex\":" << json_string(field.hex);
            out << '}';
        }
        out << ']';
    }
}

zw::zniffer::RadioFrame serial_radio(const zw::zniffer::SerialFrame& serial,
                                     const zw::zlf::Record& record,
                                     const zw::zniffer::XmlCommands* xml) {
    zw::zniffer::RadioFrame radio;
    radio.zlf_offset = serial.zlf_offset;
    radio.datetime_binary = serial.datetime_binary;
    radio.session_id = serial.session_id;
    radio.received = !record.outgoing;
    radio.beam = serial.frame_type != 0x03;
    radio.channel = serial.channel;
    radio.protocol = 6;
    radio.fcs_bytes = serial.speed > 1 ? 2 : 1;
    const auto layout = serial.speed == 3 ? 2U :
        (xml ? xml->layout_for_frequency(serial.frequency) : 0U);
    radio.region = layout == 2 ? 14 : layout == 1 ? 7 : 0;
    radio.mpdu = serial.payload;
    return radio;
}

void reply(evhttp_request* req, int code, const char* reason,
           const std::string& body, const char* type = "application/json; charset=utf-8") {
    auto* output = evbuffer_new();
    evbuffer_add(output, body.data(), body.size());
    evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type", type);
    evhttp_add_header(evhttp_request_get_output_headers(req), "Cache-Control", "no-store");
    evhttp_send_reply(req, code, reason, output);
    evbuffer_free(output);
}

std::string new_id() {
    std::random_device random;
    std::array<unsigned char, 16> bytes{};
    for (auto& b : bytes) b = static_cast<unsigned char>(random());
    return to_hex(bytes);
}

std::string query_value(const evhttp_uri* uri, const char* key) {
    evkeyvalq args{};
    const auto* query = evhttp_uri_get_query(uri);
    if (query) evhttp_parse_query_str(query, &args);
    const auto* value = evhttp_find_header(&args, key);
    std::string result = value ? value : "";
    evhttp_clear_headers(&args);
    return result;
}

std::string query_id(const evhttp_uri* uri) { return query_value(uri, "id"); }

std::string record_json(const zw::zlf::Record& r, const zw::zniffer::RadioFrame* frame,
                        const zw::zniffer::SerialFrame* serial = nullptr,
                        const zw::zniffer::S2Result* s2 = nullptr,
                        const zw::zniffer::S0Result* s0 = nullptr,
                        const zw::zniffer::XmlCommands* xml = nullptr,
                        const zw::zniffer::BasicSerialFrame* basic = nullptr) {
    std::ostringstream out;
    out << "{\"offset\":" << r.offset << ",\"timeBinary\":"
        << json_string(std::to_string(r.datetime_binary))
        << ",\"apiType\":" << unsigned(r.api_type)
        << ",\"apiName\":" << json_string(zw::zlf::api_type_name(r.api_type))
        << ",\"sessionId\":" << unsigned(r.session_id)
        << ",\"outgoing\":" << (r.outgoing ? "true" : "false")
        << ",\"length\":" << r.data.size();
    if (r.has_attachment) {
        const auto& a = r.attachment;
        const char* annotation_name = a.type == 3 ? "Network keys" :
                                      a.type == 4 ? "Frame comment" :
                                      a.type == 5 ? "Session" :
                                      a.type == 1 ? "Indexes" :
                                      a.type == 2 ? "Filters" : "Unknown attachment";
        out << ",\"attachmentType\":" << unsigned(a.type)
            << ",\"attachmentVersion\":" << unsigned(a.version)
            << ",\"annotationName\":" << json_string(annotation_name)
            << ",\"sessionName\":" << json_string(a.session_name)
            << ",\"sessionArgs\":" << json_string(a.session_args)
            << ",\"keyCount\":" << a.network_key_count
            << ",\"temporaryKeyCount\":" << a.temporary_key_count;
        if (a.type != static_cast<std::uint8_t>(zw::zlf::AttachmentType::network_keys))
            out << ",\"rawHex\":" << json_string(to_hex(r.data));
    } else if (frame) {
        if (serial) {
            out << ",\"serialVersion\":" << unsigned(serial->api_version)
                << ",\"serialFrameType\":" << unsigned(serial->frame_type)
                << ",\"systemTime\":" << serial->system_time
                << ",\"speed\":" << unsigned(serial->speed)
                << ",\"rssiRaw\":" << unsigned(serial->rssi);
        } else {
            out << ",\"dchVersion\":" << frame->dch_version
                << ",\"dchType\":" << frame->dch_message_type;
        }
        out << ",\"received\":" << (frame->received ? "true" : "false")
            << ",\"region\":" << unsigned(frame->region)
            << ",\"channel\":" << unsigned(frame->channel)
            << ",\"protocol\":" << unsigned(frame->protocol)
            << ",\"beam\":" << (frame->beam ? "true" : "false")
            << ",\"diagnostic\":" << (frame->diagnostic ? "true" : "false")
            << ",\"issue\":" << json_string(frame->issue)
            << ",\"rawHex\":" << json_string(to_hex(frame->mpdu));
        if (frame->rssi_dbm) out << ",\"rssiDbm\":" << *frame->rssi_dbm;
        if (const auto valid = zw::zniffer::validate_mpdu_crc(*frame))
            out << ",\"crcOk\":" << (*valid ? "true" : "false");
        if (const auto mpdu = zw::zniffer::summarize_mpdu(*frame)) {
            const auto layout = mpdu->long_range ? 2U :
                (frame->region == 7 || frame->region == 10 ? 1U : 0U);
            const auto xml_frame = xml ? xml->decode_frame(frame->mpdu, layout) :
                std::optional<zw::zniffer::XmlFrame>{};
            out << ",\"homeId\":" << json_string(home_id_hex(mpdu->home_id))
                << ",\"sourceNode\":" << mpdu->source_node
                << ",\"frameType\":" << json_string(xml_frame ? xml_frame->name : mpdu->type_name)
                << ",\"sequence\":" << unsigned(mpdu->sequence)
                << ",\"ackRequested\":" << (mpdu->ack_requested ? "true" : "false")
                << ",\"longRange\":" << (mpdu->long_range ? "true" : "false");
            if (xml_frame) out << ",\"headerDefinition\":" << xml_frame->definition_key;
            if (mpdu->destination_node) out << ",\"destinationNode\":" << *mpdu->destination_node;
            if (xml) {
                const auto fields = xml_frame ? xml_frame->fields :
                    xml->decode_header(frame->mpdu, layout);
                if (!fields.empty()) {
                    out << ",\"headerFields\":[";
                    bool first_field = true;
                    for (const auto& field : fields) {
                        if (!first_field) out << ',';
                        first_field = false;
                        out << "{\"name\":" << json_string(field.name)
                            << ",\"value\":" << field.value << '}';
                    }
                    out << ']';
                }
            }
            if (!mpdu->long_range && mpdu->header_type == 1) {
                const std::size_t header = xml_frame ? xml_frame->header_bytes :
                    (frame->region == 7 || frame->region == 10 ? 10 : 9);
                const std::size_t fcs = frame->fcs_bytes.value_or(
                    header == 10 || frame->channel == 0 ? 2 : 1);
                if (frame->mpdu.size() > header + fcs)
                    append_xml_command(out, xml,
                        std::span<const std::uint8_t>(frame->mpdu).subspan(
                            header, frame->mpdu.size() - header - fcs), false);
            }
        }
        if (s2 && s2->is_s2) {
            out << ",\"s2Command\":" << unsigned(s2->command)
                << ",\"s2Encrypted\":" << (s2->encrypted ? "true" : "false")
                << ",\"s2Decrypted\":" << (s2->decrypted ? "true" : "false");
            if (s2->decrypted)
            {
                out << ",\"decryptedLength\":" << s2->plaintext.size()
                    << ",\"temporaryKey\":" << (s2->temporary_key ? "true" : "false");
                if (xml && xml->decode(s2->plaintext)) append_xml_command(out, xml, s2->plaintext, true);
                else out << ",\"decryptedName\":" << json_string(decrypted_name(s2->plaintext));
                if (s2->plaintext.size() >= 2 && s2->plaintext[0] == 0x9f &&
                    s2->plaintext[1] == 0x0a)
                    out << ",\"keyMaterialRedacted\":true";
                else out << ",\"decryptedHex\":" << json_string(to_hex(s2->plaintext));
            }
            else if (!s2->issue.empty())
                out << ",\"s2Issue\":" << json_string(s2->issue);
        }
        if (s0 && s0->is_s0) {
            out << ",\"s0Command\":" << unsigned(s0->command)
                << ",\"s0Encrypted\":" << (s0->encrypted ? "true" : "false")
                << ",\"s0Decrypted\":" << (s0->decrypted ? "true" : "false");
            if (s0->decrypted) {
                out << ",\"decryptedLength\":" << s0->plaintext.size()
                    << ",\"s0FrameControl\":" << unsigned(s0->frame_control)
                    << ",\"s0Reassembled\":" << (s0->reassembled ? "true" : "false");
                if (xml && xml->decode(s0->plaintext)) append_xml_command(out, xml, s0->plaintext, true);
                else out << ",\"decryptedName\":" << json_string(decrypted_name(s0->plaintext));
                if (s0->plaintext.size() >= 2 && s0->plaintext[0] == 0x98 &&
                    s0->plaintext[1] == 0x06)
                    out << ",\"keyMaterialRedacted\":true";
                else out << ",\"decryptedHex\":" << json_string(to_hex(s0->plaintext));
            } else if (!s0->issue.empty())
                out << ",\"s0Issue\":" << json_string(s0->issue);
        }
    } else if (serial) {
        out << ",\"serialVersion\":" << unsigned(serial->api_version)
            << ",\"serialFrameType\":" << unsigned(serial->frame_type)
            << ",\"systemTime\":" << serial->system_time
            << ",\"speed\":" << unsigned(serial->speed)
            << ",\"channel\":" << unsigned(serial->channel)
            << ",\"region\":" << unsigned(serial->frequency)
            << ",\"rssiRaw\":" << unsigned(serial->rssi)
            << ",\"rawHex\":" << json_string(to_hex(serial->payload));
    } else if (basic) {
        const char* kind = basic->marker == 0x01 ? "SOF" :
                           basic->marker == 0x06 ? "ACK" :
                           basic->marker == 0x15 ? "NAK" :
                           basic->marker == 0x18 ? "CAN" : "Unknown";
        out << ",\"serialApiKind\":" << json_string(kind)
            << ",\"frameType\":" << json_string(kind)
            << ",\"rawHex\":" << json_string(to_hex(basic->bytes));
        if (basic->frame_type)
            out << ",\"serialApiFrameType\":" << json_string(
                *basic->frame_type == 0 ? "Request" :
                *basic->frame_type == 1 ? "Response" : "Unknown");
        if (basic->function) out << ",\"serialApiFunction\":" << unsigned(*basic->function);
        if (basic->checksum_ok) out << ",\"checksumOk\":" << (*basic->checksum_ok ? "true" : "false");
    } else {
        out << ",\"rawHex\":" << json_string(to_hex(r.data));
        if (r.api_type == static_cast<std::uint8_t>(zw::zlf::ApiType::text))
            out << ",\"text\":" << json_string(std::string(r.data.begin(), r.data.end()));
    }
    out << '}';
    return out.str();
}

void handle_inner(evhttp_request* req, void* context) {
    auto& state = *static_cast<State*>(context);
    const auto* uri = evhttp_request_get_evhttp_uri(req);
    const std::string path = evhttp_uri_get_path(uri) ? evhttp_uri_get_path(uri) : "/";
    const auto method = evhttp_request_get_command(req);

    if (path == "/api/health" && method == EVHTTP_REQ_GET) {
        reply(req, 200, "OK", "{\"status\":\"ok\"}");
        return;
    }
    if (path == "/api/session" && method == EVHTTP_REQ_POST) {
        const auto id = new_id();
        state.sessions.emplace(id, std::make_unique<Session>());
        reply(req, 201, "Created", "{\"id\":" + json_string(id) + "}");
        return;
    }
    if (path == "/api/live/ip" && method == EVHTTP_REQ_POST) {
        const auto host = query_value(uri, "host");
        const auto port_text = query_value(uri, "port");
        int port = 0;
        const auto [next, error] = std::from_chars(port_text.data(), port_text.data() + port_text.size(), port);
        if (host.empty() || host.size() > 253 || error != std::errc{} ||
            next != port_text.data() + port_text.size() || port < 1 || port > 65535) {
            reply(req, 400, "Bad Request", "{\"error\":\"invalid IP device host or port\"}");
            return;
        }
        const auto id = new_id();
        auto session = std::make_unique<Session>();
        session->capture = std::make_unique<zw::zniffer::TcpPtiCapture>(host, static_cast<std::uint16_t>(port));
        session->capture->start();
        state.sessions.emplace(id, std::move(session));
        reply(req, 201, "Created", "{\"id\":" + json_string(id) + "}");
        return;
    }
    if (path == "/api/live/serial" && method == EVHTTP_REQ_POST) {
        const auto device = query_value(uri, "device");
        const auto baud_text = query_value(uri, "baud");
        const auto version = query_value(uri, "version");
        if (device.rfind("/dev/", 0) != 0 || device.size() > 255 ||
            device.find("..") != std::string::npos ||
            (baud_text != "115200" && baud_text != "230400") ||
            (version != "3" && version != "4")) {
            reply(req, 400, "Bad Request", "{\"error\":\"invalid serial device settings\"}");
            return;
        }
        const auto id = new_id();
        auto session = std::make_unique<Session>();
        session->serial_capture = std::make_unique<zw::zniffer::SerialCapture>(
            device, std::stoi(baud_text), version == "4");
        session->serial_capture->start();
        state.sessions.emplace(id, std::move(session));
        reply(req, 201, "Created", "{\"id\":" + json_string(id) + "}");
        return;
    }
    if (path == "/api/live/poll" && method == EVHTTP_REQ_GET) {
        const auto found = state.sessions.find(query_id(uri));
        if (found == state.sessions.end() ||
            (!found->second->capture && !found->second->serial_capture)) {
            reply(req, 404, "Not Found", "{\"error\":\"unknown capture\"}");
            return;
        }
        auto& session = *found->second;
        const auto snapshot = session.capture ? session.capture->poll() : session.serial_capture->poll();
        std::ostringstream response;
        response << "{\"status\":" << json_string(snapshot.status)
                 << ",\"error\":" << json_string(snapshot.error)
                 << ",\"pending\":" << (snapshot.pending ? "true" : "false")
                 << ",\"rows\":[";
        bool first = true;
        for (const auto& record : snapshot.records) {
            ++session.records;
            const auto frames = zw::zniffer::decode_pti(record);
            const auto serial_frames = session.serial.feed(record);
            for (const auto& frame : frames) {
                ++session.frames;
                const auto s2 = session.s2.process(frame);
                const auto s0 = session.s0.process(frame);
                if (!first) response << ',';
                response << record_json(record, &frame, nullptr, &s2, &s0,
                                        state.xml_commands.get());
                first = false;
            }
            for (const auto& frame : serial_frames) {
                ++session.frames;
                const auto radio = serial_radio(frame, record, state.xml_commands.get());
                const auto s2 = session.s2.process(radio);
                const auto s0 = session.s0.process(radio);
                if (!first) response << ',';
                response << record_json(record, &radio, &frame, &s2, &s0,
                                        state.xml_commands.get());
                first = false;
            }
        }
        response << "]}";
        reply(req, 200, "OK", response.str());
        return;
    }
    if (path == "/api/session" && method == EVHTTP_REQ_DELETE) {
        state.sessions.erase(query_id(uri));
        reply(req, 200, "OK", "{\"closed\":true}");
        return;
    }
    if (path == "/api/replay" && method == EVHTTP_REQ_POST) {
        const auto found = state.sessions.find(query_id(uri));
        if (found == state.sessions.end() || !found->second->parser.has_header() ||
            found->second->s2.key_count() == 0 || found->second->replaying) {
            reply(req, 409, "Conflict", "{\"error\":\"no embedded keys to replay\"}");
            return;
        }
        auto& session = *found->second;
        session.parser = zw::zlf::StreamParser{};
        session.serial = zw::zniffer::SerialDecoder{};
        session.basic.reset();
        session.s2.reset_state();
        session.s0.reset_state();
        session.records = session.frames = session.basic_frames =
            session.s2_encrypted = session.s2_decrypted =
            session.s0_encrypted = session.s0_decrypted = 0;
        session.replaying = true;
        reply(req, 200, "OK", "{\"replaying\":true}");
        return;
    }
    if ((path == "/api/chunk" || path == "/api/finish") && method == EVHTTP_REQ_POST) {
        const auto id = query_id(uri);
        const auto found = state.sessions.find(id);
        if (found == state.sessions.end()) {
            reply(req, 404, "Not Found", "{\"error\":\"unknown session\"}");
            return;
        }
        auto& session = *found->second;
        try {
            if (path == "/api/finish") {
                session.parser.finish();
                std::ostringstream response;
                response << "{\"complete\":true,\"records\":" << session.records
                         << ",\"frames\":" << session.frames
                         << ",\"basicFrames\":" << session.basic_frames
                         << ",\"keyCount\":" << session.s2.key_count()
                         << ",\"s2Encrypted\":" << session.s2_encrypted
                         << ",\"s2Decrypted\":" << session.s2_decrypted
                         << ",\"s0Encrypted\":" << session.s0_encrypted
                         << ",\"s0Decrypted\":" << session.s0_decrypted
                         << ",\"version\":" << session.parser.header().version
                         << ",\"comment\":" << json_string(session.parser.header().comment) << '}';
                reply(req, 200, "OK", response.str());
                return;
            }
            auto* input = evhttp_request_get_input_buffer(req);
            const auto size = evbuffer_get_length(input);
            if (size > 256 * 1024) {
                reply(req, 413, "Payload Too Large", "{\"error\":\"chunk exceeds 256 KiB\"}");
                return;
            }
            auto* data = evbuffer_pullup(input, static_cast<ev_ssize_t>(size));
            session.parser.feed(std::span<const std::uint8_t>(data, size));
            std::ostringstream response;
            response << "{\"rows\":[";
            bool first = true;
            for (const auto& record : session.parser.take_records()) {
                ++session.records;
                if (record.has_attachment && !session.replaying) {
                    session.s2.add_keys(record.attachment);
                    session.s0.add_keys(record.attachment);
                }
                const auto frames = zw::zniffer::decode_pti(record);
                const auto serial_frames = session.serial.feed(record);
                const auto basic_frames = session.basic.feed(record);
                if (frames.empty() && serial_frames.empty() && basic_frames.empty()) {
                    if (!first) response << ',';
                    response << record_json(record, nullptr);
                    first = false;
                } else {
                    for (const auto& frame : frames) {
                        ++session.frames;
                        const auto s2 = session.s2.process(frame);
                        const auto s0 = session.s0.process(frame);
                        if (s2.encrypted) ++session.s2_encrypted;
                        if (s2.decrypted) ++session.s2_decrypted;
                        if (s0.encrypted) ++session.s0_encrypted;
                        if (s0.decrypted) ++session.s0_decrypted;
                        if (!first) response << ',';
                        response << record_json(record, &frame, nullptr, &s2, &s0,
                                                state.xml_commands.get());
                        first = false;
                    }
                }
                for (const auto& frame : serial_frames) {
                    ++session.frames;
                    const auto radio = serial_radio(frame, record, state.xml_commands.get());
                    const auto s2 = session.s2.process(radio);
                    const auto s0 = session.s0.process(radio);
                    if (s2.encrypted) ++session.s2_encrypted;
                    if (s2.decrypted) ++session.s2_decrypted;
                    if (s0.encrypted) ++session.s0_encrypted;
                    if (s0.decrypted) ++session.s0_decrypted;
                    if (!first) response << ',';
                    response << record_json(record, &radio, &frame, &s2, &s0,
                                            state.xml_commands.get());
                    first = false;
                }
                for (const auto& frame : basic_frames) {
                    ++session.basic_frames;
                    if (!first) response << ',';
                    response << record_json(record, nullptr, nullptr, nullptr, nullptr,
                                            state.xml_commands.get(), &frame);
                    first = false;
                }
            }
            response << "]}";
            reply(req, 200, "OK", response.str());
        } catch (const zw::zlf::ParseError& error) {
            reply(req, 422, "Unprocessable Content", "{\"offset\":" +
                  std::to_string(error.offset) + ",\"error\":" + json_string(error.what()) + "}");
        }
        return;
    }
    if (path == "/api/comment-header" && method == EVHTTP_REQ_POST) {
        const auto found = state.sessions.find(query_id(uri));
        if (found == state.sessions.end() || !found->second->parser.has_header()) {
            reply(req, 404, "Not Found", "{\"error\":\"unknown trace\"}");
            return;
        }
        auto* input = evhttp_request_get_input_buffer(req);
        const auto size = evbuffer_get_length(input);
        if (size > 2048) {
            reply(req, 413, "Payload Too Large", "{\"error\":\"comment is too long\"}");
            return;
        }
        auto* data = evbuffer_pullup(input, static_cast<ev_ssize_t>(size));
        try {
            const auto header = zw::zlf::header_with_comment(found->second->parser.header(),
                std::string_view(reinterpret_cast<const char*>(data), size));
            reply(req, 200, "OK", "{\"headerHex\":" + json_string(to_hex(header)) + "}");
        } catch (const std::invalid_argument& error) {
            reply(req, 422, "Unprocessable Content", "{\"error\":" +
                  json_string(error.what()) + "}");
        }
        return;
    }
    if (method == EVHTTP_REQ_GET && (path == "/" || path == "/index.html" ||
                                      path == "/app.js" || path == "/app.css")) {
        const auto name = path == "/" ? "index.html" : path.substr(1);
        const auto file = state.web_root / name;
        std::ifstream input(file, std::ios::binary);
        if (!input) { reply(req, 404, "Not Found", "missing asset"); return; }
        const std::string body(std::istreambuf_iterator<char>(input), {});
        const char* type = path == "/app.js" ? "text/javascript; charset=utf-8" :
                           path == "/app.css" ? "text/css; charset=utf-8" : "text/html; charset=utf-8";
        reply(req, 200, "OK", body, type);
        return;
    }
    reply(req, 404, "Not Found", "{\"error\":\"not found\"}");
}

void handle(evhttp_request* req, void* context) {
    try {
        handle_inner(req, context);
    } catch (const std::exception& error) {
        std::cerr << "request processing failed: " << error.what() << '\n';
        reply(req, 500, "Internal Server Error", "{\"error\":\"request processing failed\"}");
    }
}

} // namespace

int main() {
    const auto* port_text = std::getenv("ZW_PORT");
    int port = 8080;
    if (port_text) {
        const auto* end = port_text + std::char_traits<char>::length(port_text);
        const auto [next, error] = std::from_chars(port_text, end, port);
        if (error != std::errc{} || next != end || port < 1 || port > 65535) {
            std::cerr << "invalid ZW_PORT\n";
            return 2;
        }
    }
    State state;
    state.web_root = std::getenv("ZW_WEB_ROOT") ? std::getenv("ZW_WEB_ROOT") : "web";
    const auto xml_root = std::getenv("ZW_XML_ROOT") ? std::getenv("ZW_XML_ROOT") : "assets/xml";
    try {
        state.xml_commands = std::make_unique<zw::zniffer::XmlCommands>(
            (std::filesystem::path(xml_root) / "ZWave_cmd_classes.xml").string(),
            (std::filesystem::path(xml_root) / "FrameDefinition.xml").string());
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
    auto* base = event_base_new();
    if (!base) return 1;
    auto* http = evhttp_new(base);
    if (!http) { event_base_free(base); return 1; }
    evhttp_set_gencb(http, handle, &state);
    evhttp_set_max_body_size(http, 256 * 1024);
    if (evhttp_bind_socket(http, "0.0.0.0", static_cast<unsigned short>(port)) != 0) {
        std::cerr << "cannot listen on port " << port << '\n';
        evhttp_free(http);
        event_base_free(base);
        return 1;
    }
    std::cout << "Zniffer service available at http://localhost:" << port << std::endl;
    auto stop = [](evutil_socket_t, short, void* context) {
        event_base_loopbreak(static_cast<event_base*>(context));
    };
    auto* sigterm = evsignal_new(base, SIGTERM, stop, base);
    auto* sigint = evsignal_new(base, SIGINT, stop, base);
    if (sigterm) event_add(sigterm, nullptr);
    if (sigint) event_add(sigint, nullptr);
    event_base_dispatch(base);
    if (sigterm) event_free(sigterm);
    if (sigint) event_free(sigint);
    evhttp_free(http);
    event_base_free(base);
}
