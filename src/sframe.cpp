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
{
}

authentication_error::authentication_error()
  : std::runtime_error("AEAD authentication failure")
{
}

///
/// ContextBase
///

ContextBase::ContextBase(CipherSuite suite_in)
  : suite(suite_in)
{
}

ContextBase::~ContextBase() = default;

void
ContextBase::add_key(KeyID key_id, const bytes& base_key)
{
  keys.emplace(key_id, KeyAndSalt::from_base_key(suite, base_key));
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

output_bytes
ContextBase::protect(const Header& header,
                     output_bytes ciphertext,
                     input_bytes plaintext)
{
  if (ciphertext.size() < plaintext.size() + overhead(suite)) {
    throw buffer_too_small_error("Ciphertext too small for cipher overhead");
  }

  const auto& key_and_salt = keys.at(header.key_id);
  const auto aad = header.encoded();
  const auto nonce = form_nonce(header.counter, key_and_salt.salt);
  return seal(suite, key_and_salt.key, nonce, ciphertext, aad, plaintext);
}

output_bytes
ContextBase::unprotect(const Header& header,
                       output_bytes plaintext,
                       input_bytes ciphertext)
{
  if (ciphertext.size() < overhead(suite)) {
    throw buffer_too_small_error("Ciphertext too small for cipher overhead");
  }

  if (plaintext.size() < ciphertext.size() - overhead(suite)) {
    throw buffer_too_small_error("Plaintext too small for decrypted value");
  }

  const auto& key_and_salt = keys.at(header.key_id);
  const auto aad = header.encoded();
  const auto nonce = form_nonce(header.counter, key_and_salt.salt);
  return open(suite, key_and_salt.key, nonce, plaintext, aad, ciphertext);
}

static const bytes sframe_label{
  0x53, 0x46, 0x72, 0x61, 0x6d, 0x65, 0x31, 0x30 // "ContextBase10"
};
static const bytes sframe_key_label{ 0x6b, 0x65, 0x79 };        // "key"
static const bytes sframe_salt_label{ 0x73, 0x61, 0x6c, 0x74 }; // "salt"

static const bytes sframe_ctr_label{
  // "ContextBase10 AES CM AEAD"
  0x53, 0x46, 0x72, 0x61, 0x6d, 0x65, 0x31, 0x30, 0x20, 0x41,
  0x45, 0x53, 0x20, 0x43, 0x4d, 0x20, 0x41, 0x45, 0x41, 0x44,
};
static const bytes sframe_enc_label{ 0x65, 0x6e, 0x63 };        // "enc"
static const bytes sframe_auth_label{ 0x61, 0x75, 0x74, 0x68 }; // "auth"

ContextBase::KeyAndSalt
ContextBase::KeyAndSalt::from_base_key(CipherSuite suite, const bytes& base_key)
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

///
/// Context
///

Context::Context(CipherSuite suite_in)
  : ContextBase(suite_in)
{
}

Context::~Context() = default;

void
Context::add_key(KeyID key_id, const bytes& base_key)
{
  ContextBase::add_key(key_id, base_key);
  counters.emplace(key_id, 0);
}

output_bytes
Context::protect(KeyID key_id, output_bytes ciphertext, input_bytes plaintext)
{
  const auto counter = counters.at(key_id);
  counters.at(key_id) += 1;

  const auto header = Header{ key_id, counter };
  const auto aad = header.encoded();
  if (ciphertext.size() < aad.size()) {
    throw buffer_too_small_error("Ciphertext too small for SFrame header");
  }

  std::copy(aad.begin(), aad.end(), ciphertext.begin());
  auto inner_ciphertext = ciphertext.subspan(aad.size());
  auto final_ciphertext =
    ContextBase::protect(header, inner_ciphertext, plaintext);
  return ciphertext.subspan(0, aad.size() + final_ciphertext.size());
}

output_bytes
Context::unprotect(output_bytes plaintext, input_bytes ciphertext)
{
  const auto header = Header::parse(ciphertext);
  const auto inner_ciphertext = ciphertext.subspan(header.size());
  return ContextBase::unprotect(header, plaintext, inner_ciphertext);
}

///
/// MLSContext
///

MLSContext::MLSContext(CipherSuite suite_in, size_t epoch_bits_in)
  : Context(suite_in)
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
  add_epoch(epoch_id, sframe_epoch_secret, 0);
}

void
MLSContext::add_epoch(EpochID epoch_id,
                      const bytes& sframe_epoch_secret,
                      size_t sender_bits)
{
  auto epoch_index = epoch_id & epoch_mask;
  auto& epoch = epoch_cache.at(epoch_index);

  if (epoch) {
    purge_epoch(epoch->full_epoch);
  }

  epoch.reset(
    new EpochKeys(epoch_id, sframe_epoch_secret, epoch_bits, sender_bits));
}

void
MLSContext::purge_before(EpochID keeper)
{
  for (auto& ptr : epoch_cache) {
    if (ptr && ptr->full_epoch < keeper) {
      purge_epoch(ptr->full_epoch);
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
  return protect(epoch_id, sender_id, 0, ciphertext, plaintext);
}

output_bytes
MLSContext::protect(EpochID epoch_id,
                    SenderID sender_id,
                    ContextID context_id,
                    output_bytes ciphertext,
                    input_bytes plaintext)
{
  auto key_id = form_key_id(epoch_id, sender_id, context_id);
  ensure_key(key_id);
  return Context::protect(key_id, ciphertext, plaintext);
}

output_bytes
MLSContext::unprotect(output_bytes plaintext, input_bytes ciphertext)
{
  const auto header = Header::parse(ciphertext);
  const auto inner_ciphertext = ciphertext.subspan(header.size());

  ensure_key(header.key_id);
  return ContextBase::unprotect(header, plaintext, inner_ciphertext);
}

MLSContext::EpochKeys::EpochKeys(MLSContext::EpochID full_epoch_in,
                                 bytes sframe_epoch_secret_in,
                                 size_t epoch_bits,
                                 size_t sender_bits_in)
  : full_epoch(full_epoch_in)
  , sframe_epoch_secret(std::move(sframe_epoch_secret_in))
  , sender_bits(sender_bits_in)
{
  static constexpr uint64_t one = 1;
  static constexpr size_t key_id_bits = 64;

  if (sender_bits > key_id_bits - epoch_bits) {
    throw invalid_parameter_error("Sender ID field too large");
  }

  // XXX(RLB) We use 0 as a signifier that the sender takes the rest of the key
  // ID, and context IDs are not allowed.  This would be more explicit if we
  // used std::optional, but would require more modern C++.
  if (sender_bits == 0) {
    sender_bits = key_id_bits - epoch_bits;
  }

  context_bits = key_id_bits - sender_bits - epoch_bits;
  max_sender_id = (one << (sender_bits + 1)) - 1;
  max_context_id = (one << (context_bits + 1)) - 1;
}

bytes
MLSContext::EpochKeys::base_key(CipherSuite ciphersuite,
                                SenderID sender_id) const
{
  auto hash_size = cipher_digest_size(ciphersuite);
  auto enc_sender_id = bytes(8);
  encode_uint(sender_id, enc_sender_id);

  return hkdf_expand(
    ciphersuite, sframe_epoch_secret, enc_sender_id, hash_size);
}

void
MLSContext::purge_epoch(EpochID epoch_id)
{
  const auto drop_bits = epoch_id & epoch_bits;

  // Remove keys for this epoch
  for (auto i = keys.begin(); i != keys.end();) {
    if ((i->first & epoch_bits) == drop_bits) {
      i = keys.erase(i);
    } else {
      ++i;
    }
  }

  // Remove counters for this epoch
  for (auto i = counters.begin(); i != counters.end();) {
    if ((i->first & epoch_bits) == drop_bits) {
      i = counters.erase(i);
    } else {
      ++i;
    }
  }
}

KeyID
MLSContext::form_key_id(EpochID epoch_id,
                        SenderID sender_id,
                        ContextID context_id) const
{
  auto epoch_index = epoch_id & epoch_mask;
  auto& epoch = epoch_cache.at(epoch_index);
  if (!epoch) {
    throw invalid_parameter_error(
      "Unknown epoch. epoch_index: " + std::to_string(epoch_index) +
      ", sender_id:" + std::to_string(sender_id));
  }

  if (sender_id > epoch->max_sender_id) {
    throw invalid_parameter_error("Sender ID overflow");
  }

  if (context_id > epoch->max_context_id) {
    throw invalid_parameter_error("Context ID overflow");
  }

  auto sender_part = uint64_t(sender_id) << epoch_bits;
  auto context_part = uint64_t(0);
  if (epoch->context_bits > 0) {
    context_part = uint64_t(context_id) << (epoch_bits + epoch->sender_bits);
  }

  return KeyID(context_part | sender_part | epoch_index);
}

void
MLSContext::ensure_key(KeyID key_id)
{
  // If the required key already exists, we are done
  const auto epoch_index = key_id & epoch_mask;
  auto& epoch = epoch_cache.at(epoch_index);
  if (!epoch) {
    throw invalid_parameter_error("Unknown epoch: " +
                                  std::to_string(epoch_index));
  }

  if (keys.count(key_id) > 0) {
    return;
  }

  // Otherwise, derive a key and implant it
  const auto sender_id = key_id >> epoch_bits;
  Context::add_key(key_id, epoch->base_key(suite, sender_id));
  return;
}

} // namespace sframe
