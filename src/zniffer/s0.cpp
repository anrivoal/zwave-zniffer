// SPDX-License-Identifier: BSD-3-Clause
#include "zniffer/s0.hpp"
#include "zniffer/mpdu.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <memory>
#include <stdexcept>

namespace zw::zniffer {
namespace {

using Block = std::array<std::uint8_t, 16>;

Block encrypt_block(const Block& key, const Block& input) {
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    Block output{};
    int length = 0;
    if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_ecb(), nullptr,
                                   key.data(), nullptr) != 1 ||
        EVP_CIPHER_CTX_set_padding(ctx.get(), 0) != 1 ||
        EVP_EncryptUpdate(ctx.get(), output.data(), &length, input.data(), 16) != 1 ||
        length != 16)
        throw std::runtime_error("S0 AES key derivation failed");
    return output;
}

std::array<std::uint8_t, 8> authenticate(const Block& auth_key,
                                         std::span<const std::uint8_t> data) {
    std::vector<std::uint8_t> padded(data.begin(), data.end());
    padded.resize((padded.size() + 15) / 16 * 16, 0);
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    std::vector<std::uint8_t> ciphertext(padded.size() + 16);
    Block zero{};
    int length = 0;
    if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_aes_128_cbc(), nullptr,
                                   auth_key.data(), zero.data()) != 1 ||
        EVP_CIPHER_CTX_set_padding(ctx.get(), 0) != 1 ||
        EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &length,
                          padded.data(), static_cast<int>(padded.size())) != 1 ||
        length != static_cast<int>(padded.size()))
        throw std::runtime_error("S0 MAC calculation failed");
    std::array<std::uint8_t, 8> mac{};
    std::copy_n(ciphertext.begin() + length - 16, 8, mac.begin());
    return mac;
}

std::vector<std::uint8_t> decrypt_ofb(const Block& encryption_key, const Block& iv,
                                      std::span<const std::uint8_t> ciphertext) {
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> ctx(
        EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    std::vector<std::uint8_t> plaintext(ciphertext.size() + 16);
    int length = 0;
    if (!ctx || EVP_DecryptInit_ex(ctx.get(), EVP_aes_128_ofb(), nullptr,
                                   encryption_key.data(), iv.data()) != 1 ||
        EVP_DecryptUpdate(ctx.get(), plaintext.data(), &length,
                          ciphertext.data(), static_cast<int>(ciphertext.size())) != 1 ||
        length != static_cast<int>(ciphertext.size()))
        throw std::runtime_error("S0 AES-OFB decryption failed");
    plaintext.resize(length);
    return plaintext;
}

} // namespace

S0Result::~S0Result() {
    if (!plaintext.empty()) OPENSSL_cleanse(plaintext.data(), plaintext.size());
}

S0Decoder::S0Decoder() {
    // Match the C# Zniffer's public fallback keys used during inclusion.
    Block auth_base{};
    auth_base.fill(0x55);
    Block encryption_base{};
    encryption_base.fill(0xaa);
    auto add_preset = [&](Block raw) {
        Key key;
        key.raw = raw;
        key.auth = encrypt_block(key.raw, auth_base);
        key.encryption = encrypt_block(key.raw, encryption_base);
        keys_.push_back(key);
    };
    Block one{};
    one.fill(0x01);
    add_preset(one);
    for (int first = 0xc0; first <= 0xc4; ++first) {
        Block raw{};
        raw[0] = static_cast<std::uint8_t>(first);
        add_preset(raw);
    }
    add_preset(Block{});
}

S0Decoder::~S0Decoder() {
    reset_state();
    for (auto& key : keys_) {
        OPENSSL_cleanse(key.raw.data(), key.raw.size());
        OPENSSL_cleanse(key.auth.data(), key.auth.size());
        OPENSSL_cleanse(key.encryption.data(), key.encryption.size());
    }
}

void S0Decoder::add_keys(const zlf::Attachment& attachment) {
    if (attachment.type != static_cast<std::uint8_t>(zlf::AttachmentType::network_keys)) return;
    Block auth_base{};
    auth_base.fill(0x55);
    Block encryption_base{};
    encryption_base.fill(0xaa);
    for (const auto& group : attachment.network_key_groups) {
        if (group.temporary) continue;
        for (const auto& raw : group.keys) {
            Key key;
            key.home_id = group.home_id;
            key.raw = raw;
            key.auth = encrypt_block(key.raw, auth_base);
            key.encryption = encrypt_block(key.raw, encryption_base);
            keys_.push_back(key);
        }
    }
}

void S0Decoder::reset_state() {
    for (auto& [id, nonce] : nonces_) {
        (void)id;
        OPENSSL_cleanse(nonce.data(), nonce.size());
    }
    nonces_.clear();
    for (auto& [id, fragment] : fragments_) {
        (void)id;
        if (!fragment.empty()) OPENSSL_cleanse(fragment.data(), fragment.size());
    }
    fragments_.clear();
}

S0Result S0Decoder::process(const RadioFrame& frame) {
    S0Result result;
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
    if (command[0] != 0x98) return result;
    result.is_s0 = true;
    result.command = command[1];
    const auto source = mpdu->source_node;
    const auto destination = *mpdu->destination_node;
    const auto home = mpdu->home_id;
    if (command[1] == 0x80 && command.size() >= 10) {
        NonceId id{home, source, destination, command[2]};
        auto& nonce = nonces_[id];
        std::copy_n(command.begin() + 2, 8, nonce.begin());
        if (nonces_.size() > 256) nonces_.erase(nonces_.begin());
        return result;
    }
    if (command[1] != 0x81 && command[1] != 0xc1) return result;
    result.encrypted = true;
    if (command.size() < 20) { result.issue = "short S0 encapsulation"; return result; }
    const auto sender_nonce = command.subspan(2, 8);
    const auto ciphertext = command.subspan(10, command.size() - 19);
    const auto nonce_id = command[command.size() - 9];
    const auto mac = command.last(8);
    const auto nonce_it = nonces_.find(NonceId{home, destination, source, nonce_id});
    if (nonce_it == nonces_.end()) { result.issue = "no matching S0 nonce"; return result; }
    Block iv{};
    std::copy(sender_nonce.begin(), sender_nonce.end(), iv.begin());
    std::copy(nonce_it->second.begin(), nonce_it->second.end(), iv.begin() + 8);
    std::vector<std::uint8_t> authenticated;
    authenticated.reserve(20 + ciphertext.size());
    authenticated.insert(authenticated.end(), iv.begin(), iv.end());
    authenticated.push_back(command[1]);
    authenticated.push_back(static_cast<std::uint8_t>(source));
    authenticated.push_back(static_cast<std::uint8_t>(destination));
    authenticated.push_back(static_cast<std::uint8_t>(ciphertext.size()));
    authenticated.insert(authenticated.end(), ciphertext.begin(), ciphertext.end());
    for (const auto& key : keys_) {
        if (key.home_id != 0 && key.home_id != home) continue;
        const auto expected = authenticate(key.auth, authenticated);
        if (CRYPTO_memcmp(expected.data(), mac.data(), 8) != 0) continue;
        auto clear = decrypt_ofb(key.encryption, iv, ciphertext);
        if (clear.empty()) { result.issue = "empty S0 plaintext"; return result; }
        result.frame_control = clear[0];
        result.plaintext.assign(clear.begin() + 1, clear.end());
        result.decrypted = true;
        OPENSSL_cleanse(clear.data(), clear.size());
        const bool sequenced = (result.frame_control & 0x10) != 0;
        const bool second = (result.frame_control & 0x20) != 0;
        const FragmentId fragment{home, source, destination,
                                  static_cast<std::uint8_t>(result.frame_control & 0x0f)};
        if (sequenced && !second) {
            fragments_[fragment] = result.plaintext;
        } else if (sequenced && second) {
            if (const auto part = fragments_.find(fragment); part != fragments_.end()) {
                std::vector<std::uint8_t> combined = std::move(part->second);
                combined.insert(combined.end(), result.plaintext.begin(), result.plaintext.end());
                result.plaintext = std::move(combined);
                result.reassembled = true;
                fragments_.erase(part);
            }
        }
        return result;
    }
    result.issue = keys_.empty() ? "no S0 keys" : "S0 authentication failed";
    return result;
}

} // namespace zw::zniffer
