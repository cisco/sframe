#include <sframe/sframe.h>

#include "crypto.h"
#include "header.h"

#include <algorithm>
#include <array>
#include <iomanip>
#include <iostream>
#include <stdexcept>
#include <tuple>

namespace sframe {

std::ostream&
operator<<(std::ostream& str, const input_bytes data)
{
  str.flags(std::ios::hex);
  for (const auto& byte : data) {
    str << std::setw(2) << std::setfill('0') << int(byte);
  }
  return str;
}

///
/// Errors
///

unsupported_ciphersuite_error::unsupported_ciphersuite_error()
  : std::runtime_error("Unsupported ciphersuite")
{}

authentication_error::authentication_error()
  : std::runtime_error("AEAD authentication failure")
{}

///
/// Context
///

Context::Context(CipherSuite suite_in)
  : SFrame(suite_in)
{}

static const bytes sframe_label{
  0x53, 0x46, 0x72, 0x61, 0x6d, 0x65, 0x31, 0x30 // "SFrame10"
};
static const bytes sframe_key_label{ 0x6b, 0x65, 0x79 };        // "key"
static const bytes sframe_salt_label{ 0x73, 0x61, 0x6c, 0x74 }; // "salt"

static const bytes sframe_ctr_label{
  // "SFrame10 AES CM AEAD"
  0x53, 0x46, 0x72, 0x61, 0x6d, 0x65, 0x31, 0x30, 0x20, 0x41,
  0x45, 0x53, 0x20, 0x43, 0x4d, 0x20, 0x41, 0x45, 0x41, 0x44,
};
static const bytes sframe_enc_label{ 0x65, 0x6e, 0x63 };        // "enc"
static const bytes sframe_auth_label{ 0x61, 0x75, 0x74, 0x68 }; // "auth"

SFrame::KeyAndSalt
SFrame::KeyAndSalt::from_base_key(CipherSuite suite, const bytes& base_key)
{
  auto key_size = cipher_key_size(suite);
  auto nonce_size = cipher_nonce_size(suite);
  auto hash_size = cipher_digest_size(suite);

  auto secret = hkdf_extract(suite, sframe_label, base_key);
  auto key = hkdf_expand(suite, secret, sframe_key_label, key_size);
  auto salt = hkdf_expand(suite, secret, sframe_salt_label, nonce_size);

  // If using CTR+HMAC, set key = enc_key || auth_key
  if (suite == CipherSuite::AES_CM_128_HMAC_SHA256_4 ||
      suite == CipherSuite::AES_CM_128_HMAC_SHA256_8) {
    secret = hkdf_extract(suite, sframe_ctr_label, key);

    auto main_key = key;
    auto enc_key = hkdf_expand(suite, secret, sframe_enc_label, key_size);
    auto auth_key = hkdf_expand(suite, secret, sframe_auth_label, hash_size);

    key = enc_key;
    key.insert(key.end(), auth_key.begin(), auth_key.end());
  }

  return KeyAndSalt{ key, salt, 0 };
}

static bytes
form_nonce(Counter ctr, const bytes& salt)
{
  auto nonce = salt;
  for (size_t i = 0; i < sizeof(ctr); i++) {
    nonce[nonce.size() - i - 1] ^= uint8_t(ctr >> (8 * i));
  }

  return nonce;
}

SFrame::SFrame(CipherSuite suite_in)
  : suite(suite_in)
{}

SFrame::~SFrame() = default;

void
SFrame::add_key(KeyID key_id, const bytes& base_key)
{
  keys.emplace(key_id, KeyAndSalt::from_base_key(suite, base_key));
}

output_bytes
SFrame::_protect(KeyID key_id, Counter ctr, output_bytes ciphertext, input_bytes plaintext)
{
  const auto& key_and_salt = keys.at(key_id);
  const auto header = Header{ key_id, ctr };
  const auto aad = header.encoded();

  if (ciphertext.size() < aad.size()) {
    throw buffer_too_small_error("Ciphertext too small for SFrame header");
  }

  std::copy(aad.begin(), aad.end(), ciphertext.begin());
  auto inner_ciphertext = ciphertext.subspan(aad.size());

  if (inner_ciphertext.size() < plaintext.size() + overhead(suite)) {
    throw buffer_too_small_error("Ciphertext too small for ciphertext");
  }

  const auto nonce = form_nonce(ctr, key_and_salt.salt);
  auto final_ciphertext =
    seal(suite, key_and_salt.key, nonce, inner_ciphertext, aad, plaintext);
  return ciphertext.subspan(0, aad.size() + final_ciphertext.size());
}

output_bytes
SFrame::_unprotect(output_bytes plaintext, input_bytes ciphertext)
{
  const auto header = Header::parse(ciphertext);
  const auto aad = header.encoded();
  const auto inner_ciphertext = ciphertext.subspan(aad.size());

  const auto& key_and_salt = keys.at(header.key_id);
  const auto nonce = form_nonce(header.counter, key_and_salt.salt);
  return open(suite, key_and_salt.key, nonce, plaintext, aad, inner_ciphertext);
}

void
Context::add_key(KeyID key_id, const bytes& base_key)
{
  SFrame::add_key(key_id, base_key);
  counters.emplace(key_id, 0);
}

output_bytes
Context::protect(KeyID key_id, output_bytes ciphertext, input_bytes plaintext)
{
  const auto ctr = counters.at(key_id);
  counters.at(key_id) += 1;

  return _protect(key_id, ctr, ciphertext, plaintext);
}

output_bytes
Context::unprotect(output_bytes plaintext, input_bytes ciphertext)
{
  return _unprotect(plaintext, ciphertext);
}

#if 0
///
/// MLSContext
///

MLSContext::MLSContext(CipherSuite suite_in, size_t epoch_bits_in)
  : SFrame(suite_in)
  , epoch_bits(epoch_bits_in)
  , epoch_mask((size_t(1) << epoch_bits_in) - 1)
  , epoch_cache(size_t(1) << epoch_bits_in)
{
  std::for_each(epoch_cache.begin(),
                epoch_cache.end(),
                [&](std::unique_ptr<EpochKeys>& ptr) { ptr.reset(nullptr); });
}

void
MLSContext::add_epoch(EpochID epoch_id, const bytes& sframe_epoch_secret)
{
  auto epoch_index = epoch_id & epoch_mask;
  epoch_cache.at(epoch_index)
    .reset(new EpochKeys(epoch_id, sframe_epoch_secret, 0));
}

void
MLSContext::add_epoch(EpochID epoch_id,
                      const bytes& sframe_epoch_secret,
                      size_t sender_bits)
{
  auto epoch_index = epoch_id & epoch_mask;
  epoch_cache.at(epoch_index)
    .reset(new EpochKeys(epoch_id, sframe_epoch_secret, sender_bits));
}

void
MLSContext::purge_before(EpochID keeper)
{
  for (auto& ptr : epoch_cache) {
    if (ptr && ptr->full_epoch < keeper) {
      ptr.reset(nullptr);
    }
  }
}

output_bytes
MLSContext::protect(EpochID epoch_id,
                    SenderID sender_id,
                    output_bytes ciphertext,
                    input_bytes plaintext)
{
  auto epoch_index = epoch_id & epoch_mask;
  auto key_id = KeyID((uint64_t(sender_id) << epoch_bits) | epoch_index);
  return _protect(key_id, ciphertext, plaintext);
}

output_bytes
MLSContext::protect(EpochID epoch_id,
                    SenderID sender_id,
                    ContextID context_id,
                    output_bytes ciphertext,
                    input_bytes plaintext)
{
  auto epoch_index = epoch_id & epoch_mask;
  auto& epoch = epoch_cache.at(epoch_index);
  if (!epoch) {
    throw invalid_parameter_error(
      "Unknown epoch. epoch_index: " + std::to_string(epoch_index) +
      ", sender_id:" + std::to_string(sender_id));
  }

  auto sender_bits = epoch->sender_bits;
  if (sender_id >= (uint64_t(1) << sender_bits)) {
    throw invalid_parameter_error(
      "Sender ID too large: " + std::to_string(sender_id) + " > " +
      std::to_string(1 << sender_bits) +
      " sender_bits:" + std::to_string(sender_bits));
  }

  auto context_part = uint64_t(context_id) << (epoch_bits + sender_bits);
  auto sender_part = uint64_t(sender_id) << epoch_bits;
  auto key_id = KeyID(context_part | sender_part | epoch_index);
  return _protect(key_id, ciphertext, plaintext);
}

output_bytes
MLSContext::unprotect(output_bytes plaintext, input_bytes ciphertext)
{
  return _unprotect(plaintext, ciphertext);
}

MLSContext::EpochKeys::EpochKeys(MLSContext::EpochID full_epoch_in,
                                 bytes sframe_epoch_secret_in,
                                 size_t sender_bits_in)
  : full_epoch(full_epoch_in)
  , sframe_epoch_secret(std::move(sframe_epoch_secret_in))
  , sender_bits(sender_bits_in)
{}

SFrame::KeyState&
MLSContext::EpochKeys::get(CipherSuite ciphersuite, SenderID sender_id)
{
  auto it = sender_keys.find(sender_id);
  if (it != sender_keys.end()) {
    return it->second;
  }

  auto hash_size = cipher_digest_size(ciphersuite);
  auto enc_sender_id = bytes(8);
  encode_uint(sender_id, enc_sender_id);

  auto sender_base_key =
    hkdf_expand(ciphersuite, sframe_epoch_secret, enc_sender_id, hash_size);
  auto key_state = KeyState::from_base_key(ciphersuite, sender_base_key);
  sender_keys.insert({ sender_id, std::move(key_state) });

  return sender_keys.at(sender_id);
}

SFrame::KeyState&
MLSContext::get_state(KeyID key_id)
{
  const auto epoch_index = EpochID(key_id & epoch_mask);
  const auto sender_id = SenderID(key_id >> epoch_bits);

  auto& epoch = epoch_cache.at(epoch_index);
  if (!epoch) {
    throw invalid_parameter_error(
      "Unknown epoch. epoch_index: " + std::to_string(epoch_index) +
      ", sender_id:" + std::to_string(sender_id));
  }

  return epoch->get(suite, sender_id);
}
#endif // 0

} // namespace sframe
