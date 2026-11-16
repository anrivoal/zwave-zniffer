// SPDX-License-Identifier: BSD-3-Clause
#pragma once

#include "zniffer/radio.hpp"
#include "zniffer/zlf.hpp"

#include <array>
#include <compare>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace zw::zniffer {

struct S0Result {
    S0Result() = default;
    ~S0Result();
    S0Result(S0Result&&) = default;
    S0Result& operator=(S0Result&&) = delete;
    S0Result(const S0Result&) = delete;
    S0Result& operator=(const S0Result&) = delete;
    bool is_s0{};
    bool encrypted{};
    bool decrypted{};
    bool reassembled{};
    std::uint8_t command{};
    std::uint8_t frame_control{};
    std::vector<std::uint8_t> plaintext;
    std::string issue;
};

class S0Decoder {
public:
    ~S0Decoder();
    S0Decoder();
    S0Decoder(const S0Decoder&) = delete;
    S0Decoder& operator=(const S0Decoder&) = delete;
    void add_keys(const zlf::Attachment& attachment);
    void reset_state();
    S0Result process(const RadioFrame& frame);

private:
    struct Key {
        std::uint32_t home_id{};
        std::array<std::uint8_t, 16> raw{};
        std::array<std::uint8_t, 16> auth{};
        std::array<std::uint8_t, 16> encryption{};
    };
    struct NonceId {
        std::uint32_t home_id{};
        std::uint16_t sender{};
        std::uint16_t receiver{};
        std::uint8_t id{};
        auto operator<=>(const NonceId&) const = default;
    };
    struct FragmentId {
        std::uint32_t home_id{};
        std::uint16_t sender{};
        std::uint16_t receiver{};
        std::uint8_t sequence{};
        auto operator<=>(const FragmentId&) const = default;
    };
    std::vector<Key> keys_;
    std::map<NonceId, std::array<std::uint8_t, 8>> nonces_;
    std::map<FragmentId, std::vector<std::uint8_t>> fragments_;
};

} // namespace zw::zniffer
