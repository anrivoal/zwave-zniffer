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

struct S2Result {
    S2Result() = default;
    ~S2Result();
    S2Result(S2Result&&) = default;
    S2Result& operator=(S2Result&&) = delete;
    S2Result(const S2Result&) = delete;
    S2Result& operator=(const S2Result&) = delete;
    bool is_s2{};
    bool encrypted{};
    bool decrypted{};
    bool temporary_key{};
    std::uint8_t command{};
    std::vector<std::uint8_t> plaintext;
    std::string issue;
};

// Offline Zniffer decoder. Keys and SPAN state exist only for this session.
class S2Decoder {
public:
    ~S2Decoder();
    S2Decoder() = default;
    S2Decoder(const S2Decoder&) = delete;
    S2Decoder& operator=(const S2Decoder&) = delete;
    void add_keys(const zlf::Attachment& attachment);
    void reset_state();
    std::size_t key_count() const noexcept;
    S2Result process(const RadioFrame& frame);

private:
    struct Key {
        std::uint32_t home_id{};
        bool temporary{};
        std::array<std::uint8_t, 16> raw{};
        std::array<std::uint8_t, 16> ccm{};
        std::array<std::uint8_t, 32> personalization{};
    };
    struct Pair {
        std::uint32_t home_id{};
        std::uint16_t first{};
        std::uint16_t second{};
        auto operator<=>(const Pair&) const = default;
    };
    struct Drbg {
        std::array<std::uint8_t, 16> key{};
        std::array<std::uint8_t, 16> value{};
        void initialize(const std::array<std::uint8_t, 32>& entropy,
                        const std::array<std::uint8_t, 32>& personalization);
        std::array<std::uint8_t, 13> next_nonce();
    private:
        void update(const std::array<std::uint8_t, 32>* data);
    };
    struct Span {
        std::array<std::uint8_t, 16> receiver_ei{};
        bool has_receiver{};
        Drbg drbg;
        std::size_t key_index{};
        bool established{};
    };
    std::vector<Key> keys_;
    std::map<Pair, Span> spans_;
};

} // namespace zw::zniffer
