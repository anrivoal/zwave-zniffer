// SPDX-License-Identifier: BSD-3-Clause
#include "zniffer/s2.hpp"
#include "zniffer/mpdu.hpp"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/crypto.h>

#include <algorithm>
#include <memory>
#include <stdexcept>

namespace zw::zniffer {
namespace {

using Block = std::array<std::uint8_t, 16>;
using Seed = std::array<std::uint8_t, 32>;

Block encrypt_block(const Block& key, const Block& input) {
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    Block out{};
    int length = 0;
    if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_ecb(), nullptr,
                                   key.data(), nullptr) != 1 ||
        EVP_CIPHER_CTX_set_padding(ctx.get(), 0) != 1 ||
        EVP_EncryptUpdate(ctx.get(), out.data(), &length, input.data(), 16) != 1 ||
        length != 16)
        throw std::runtime_error("AES block encryption failed");
    return out;
}

Block cmac(std::span<const std::uint8_t> data, const Block& key) {
    std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)> mac(
        EVP_MAC_fetch(nullptr, "CMAC", nullptr), EVP_MAC_free);
    std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> ctx(
        mac ? EVP_MAC_CTX_new(mac.get()) : nullptr, EVP_MAC_CTX_free);
    char cipher[] = "AES-128-CBC";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER, cipher, 0),
        OSSL_PARAM_construct_end()
    };
    Block out{};
    std::size_t length = 0;
    if (!ctx || EVP_MAC_init(ctx.get(), key.data(), key.size(), params) != 1 ||
        EVP_MAC_update(ctx.get(), data.data(), data.size()) != 1 ||
        EVP_MAC_final(ctx.get(), out.data(), &length, out.size()) != 1 || length != 16)
        throw std::runtime_error("AES-CMAC failed");
    return out;
}

void increment(Block& value) {
    for (int i = 15; i >= 0; --i) if (++value[i] != 0) break;
}

std::vector<std::uint8_t> concat(std::span<const std::uint8_t> first,
                                 std::span<const std::uint8_t> second,
                                 std::span<const std::uint8_t> third = {}) {
    std::vector<std::uint8_t> out;
    out.reserve(first.size() + second.size() + third.size());
    out.insert(out.end(), first.begin(), first.end());
    out.insert(out.end(), second.begin(), second.end());
    out.insert(out.end(), third.begin(), third.end());
    return out;
}

void derive_key(const Block& network, bool temporary, Block& ccm, Seed& personalization) {
    std::array<std::uint8_t, 16> label{};
    label.fill(temporary ? 0x88 : 0x55);
    label[15] = 1;
    const auto t1 = cmac(label, network);
    label[15] = 2;
    const auto t2 = cmac(concat(t1, label), network);
    label[15] = 3;
    const auto t3 = cmac(concat(t2, label), network);
    ccm = t1;
    std::copy(t2.begin(), t2.end(), personalization.begin());
    std::copy(t3.begin(), t3.end(), personalization.begin() + 16);
}

Seed derive_entropy(const Block& sender, const Block& receiver) {
    Block nonce_constant{};
    nonce_constant.fill(0x26);
    const auto prk = cmac(concat(sender, receiver), nonce_constant);
    std::array<std::uint8_t, 32> label{};
    label.fill(0x88);
    label[15] = 0;
    label[31] = 1;
    const auto t1 = cmac(label, prk);
    std::array<std::uint8_t, 16> second{};
    second.fill(0x88);
    second[15] = 2;
    const auto t2 = cmac(concat(t1, second), prk);
    Seed entropy{};
    std::copy(t1.begin(), t1.end(), entropy.begin());
    std::copy(t2.begin(), t2.end(), entropy.begin() + 16);
    return entropy;
}

bool decrypt_ccm(const Block& key, const std::array<std::uint8_t, 13>& nonce,
                 std::span<const std::uint8_t> aad,
                 std::span<const std::uint8_t> ciphertext,
                 std::span<const std::uint8_t> tag,
                 std::vector<std::uint8_t>& plaintext) {
    if (tag.size() != 8) return false;
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx || EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_ccm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_SET_IVLEN, 13, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_SET_TAG, 8,
                            const_cast<std::uint8_t*>(tag.data())) != 1 ||
        EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, key.data(), nonce.data()) != 1)
        throw std::runtime_error("AES-CCM initialization failed");
    int length = 0;
    if (EVP_DecryptUpdate(ctx.get(), nullptr, &length, nullptr,
                          static_cast<int>(ciphertext.size())) != 1 ||
        EVP_DecryptUpdate(ctx.get(), nullptr, &length, aad.data(),
                          static_cast<int>(aad.size())) != 1)
        throw std::runtime_error("AES-CCM authentication data failed");
    plaintext.resize(ciphertext.size());
    const auto okay = EVP_DecryptUpdate(ctx.get(), plaintext.data(), &length,
                                        ciphertext.data(), static_cast<int>(ciphertext.size())) == 1;
    if (!okay) plaintext.clear();
    return okay;
}

} // namespace

S2Result::~S2Result() {
    if (!plaintext.empty()) OPENSSL_cleanse(plaintext.data(), plaintext.size());
}

S2Decoder::~S2Decoder() {
    reset_state();
    for (auto& key : keys_) {
        OPENSSL_cleanse(key.raw.data(), key.raw.size());
        OPENSSL_cleanse(key.ccm.data(), key.ccm.size());
        OPENSSL_cleanse(key.personalization.data(), key.personalization.size());
    }
}

void S2Decoder::Drbg::update(const Seed* data) {
    Seed temp{};
    for (int block = 0; block < 2; ++block) {
        increment(value);
        const auto encrypted = encrypt_block(key, value);
        std::copy(encrypted.begin(), encrypted.end(), temp.begin() + block * 16);
    }
    if (data) for (std::size_t i = 0; i < 32; ++i) temp[i] ^= (*data)[i];
    std::copy_n(temp.begin(), 16, key.begin());
    std::copy_n(temp.begin() + 16, 16, value.begin());
}

void S2Decoder::Drbg::initialize(const Seed& entropy, const Seed& personalization) {
    key.fill(0);
    value.fill(0);
    Seed combined{};
    for (std::size_t i = 0; i < 32; ++i) combined[i] = entropy[i] ^ personalization[i];
    update(&combined);
}

std::array<std::uint8_t, 13> S2Decoder::Drbg::next_nonce() {
    increment(value);
    const auto block = encrypt_block(key, value);
    update(nullptr);
    std::array<std::uint8_t, 13> nonce{};
    std::copy_n(block.begin(), 13, nonce.begin());
    return nonce;
}

void S2Decoder::add_keys(const zlf::Attachment& attachment) {
    if (attachment.type != static_cast<std::uint8_t>(zlf::AttachmentType::network_keys)) return;
    for (const auto& group : attachment.network_key_groups) {
        for (const auto& raw : group.keys) {
            Key key;
            key.home_id = group.home_id;
            key.temporary = group.temporary;
            key.raw = raw;
            derive_key(key.raw, key.temporary, key.ccm, key.personalization);
            keys_.push_back(key);
        }
    }
}

void S2Decoder::reset_state() {
    for (auto& [pair, span] : spans_) {
        (void)pair;
        OPENSSL_cleanse(span.receiver_ei.data(), span.receiver_ei.size());
        OPENSSL_cleanse(span.drbg.key.data(), span.drbg.key.size());
        OPENSSL_cleanse(span.drbg.value.data(), span.drbg.value.size());
    }
    spans_.clear();
}
std::size_t S2Decoder::key_count() const noexcept { return keys_.size(); }

S2Result S2Decoder::process(const RadioFrame& frame) {
    S2Result result;
    const auto mpdu = summarize_mpdu(frame);
    const auto& bytes = frame.mpdu;
    if (!mpdu || mpdu->type_name != "Singlecast" || mpdu->long_range ||
        !mpdu->destination_node || bytes[7] != bytes.size()) return result;
    const bool three_channel = frame.region == 7 || frame.region == 10;
    const std::size_t header_size = three_channel ? 10 : 9;
    const std::size_t fcs_size = frame.fcs_bytes.value_or(three_channel || frame.channel == 0 ? 2 : 1);
    if (bytes.size() < header_size + fcs_size + 2) return result;
    const auto command = std::span<const std::uint8_t>(bytes).subspan(
        header_size, bytes.size() - header_size - fcs_size);
    if (command.size() < 2 || command[0] != 0x9f) return result;
    result.is_s2 = true;
    result.command = command[1];
    const Pair pair{mpdu->home_id,
                    std::min(mpdu->source_node, *mpdu->destination_node),
                    std::max(mpdu->source_node, *mpdu->destination_node)};
    if (command[1] == 2 && command.size() >= 20 && (command[3] & 1)) {
        auto& span = spans_[pair];
        std::copy_n(command.begin() + 4, 16, span.receiver_ei.begin());
        span.has_receiver = true;
        span.established = false;
        return result;
    }
    if (command[1] != 3) return result;
    result.encrypted = true;
    if (command.size() < 12) { result.issue = "short S2 encapsulation"; return result; }
    const auto properties = command[3];
    std::size_t at = 4;
    Block sender_ei{};
    bool has_sender_ei = false;
    if (properties & 1) {
        bool more = true;
        while (more) {
            if (at + 2 > command.size() - 8) { result.issue = "truncated S2 extension"; return result; }
            const auto length = command[at];
            if (length < 2 || at + length > command.size() - 8) {
                result.issue = "invalid S2 extension length"; return result;
            }
            const auto type = command[at + 1] & 0x3f;
            more = (command[at + 1] & 0x80) != 0;
            if (type == 1 && length == 18) {
                std::copy_n(command.begin() + at + 2, 16, sender_ei.begin());
                has_sender_ei = true;
            }
            at += length;
        }
    }
    auto found = spans_.find(pair);
    if (found == spans_.end() || !found->second.has_receiver) {
        result.issue = "no receiver entropy input";
        return result;
    }
    auto& span = found->second;
    if (has_sender_ei) span.established = false;
    std::vector<std::uint8_t> aad;
    aad.reserve(8 + at - 2);
    aad.push_back(static_cast<std::uint8_t>(mpdu->source_node));
    aad.push_back(static_cast<std::uint8_t>(*mpdu->destination_node));
    for (int shift = 24; shift >= 0; shift -= 8)
        aad.push_back(static_cast<std::uint8_t>(mpdu->home_id >> shift));
    aad.push_back(static_cast<std::uint8_t>(command.size() >> 8));
    aad.push_back(static_cast<std::uint8_t>(command.size()));
    aad.insert(aad.end(), command.begin() + 2, command.begin() + at);
    const auto ciphertext = command.subspan(at, command.size() - at - 8);
    const auto tag = command.last(8);
    auto attempt = [&](Drbg generator, std::size_t key_index) -> bool {
        for (int i = 0; i < 16; ++i) {
            const auto nonce = generator.next_nonce();
            std::vector<std::uint8_t> plaintext;
            if (!decrypt_ccm(keys_[key_index].ccm, nonce, aad, ciphertext, tag, plaintext)) continue;
            span.drbg = generator;
            span.key_index = key_index;
            span.established = true;
            result.decrypted = true;
            result.temporary_key = keys_[key_index].temporary;
            if (properties & 2) {
                std::size_t offset = 0;
                bool more = true;
                while (more && offset + 2 <= plaintext.size()) {
                    const auto length = plaintext[offset];
                    if (length < 2 || offset + length > plaintext.size()) break;
                    more = (plaintext[offset + 1] & 0x80) != 0;
                    offset += length;
                }
                result.plaintext.assign(plaintext.begin() + offset, plaintext.end());
            } else result.plaintext = std::move(plaintext);
            return true;
        }
        return false;
    };
    if (span.established && !has_sender_ei && attempt(span.drbg, span.key_index)) return result;
    if (has_sender_ei) {
        const auto entropy = derive_entropy(sender_ei, span.receiver_ei);
        for (std::size_t i = 0; i < keys_.size(); ++i) {
            if (keys_[i].home_id != 0 && keys_[i].home_id != pair.home_id) continue;
            Drbg generator;
            generator.initialize(entropy, keys_[i].personalization);
            if (attempt(generator, i)) return result;
        }
    }
    result.issue = keys_.empty() ? "no S2 keys" :
                   has_sender_ei ? "S2 authentication failed" : "no synchronized SPAN";
    return result;
}

} // namespace zw::zniffer
