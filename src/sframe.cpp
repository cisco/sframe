#include <sframe/sframe.h>

#include "crypto.h"
#include "header.h"

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

SFrame::KeyState
SFrame::KeyState::from_base_key(CipherSuite suite, const bytes& base_key)
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

  return KeyState{ key, salt, 0 };
}

void
Context::add_key(KeyID key_id, const bytes& base_key)
{
  auto key_state = KeyState::from_base_key(suite, base_key);
  state.insert_or_assign(key_id, std::move(key_state));
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

SFrame::~SFrame()
{}

output_bytes
SFrame::_protect(KeyID key_id, output_bytes ciphertext, input_bytes plaintext)
{
  auto& state = get_state(key_id);
  const auto ctr = state.counter;
  state.counter += 1;

  auto hdr_size = Header{ key_id, ctr }.encode(ciphertext);
  auto header = ciphertext.subspan(0, hdr_size);
  auto inner_ciphertext = ciphertext.subspan(hdr_size);

  const auto nonce = form_nonce(ctr, state.salt);
  auto final_ciphertext =
    seal(suite, state.key, nonce, inner_ciphertext, header, plaintext);
  return ciphertext.subspan(0, hdr_size + final_ciphertext.size());
}

output_bytes
SFrame::_unprotect(output_bytes plaintext, input_bytes ciphertext)
{
  auto [header, aad] = Header::decode(ciphertext);
  auto inner_ciphertext = ciphertext.subspan(aad.size());

  auto& state = get_state(header.key_id);
  const auto nonce = form_nonce(header.counter, state.salt);
  return open(suite, state.key, nonce, plaintext, aad, inner_ciphertext);
}

output_bytes
Context::protect(KeyID key_id, output_bytes ciphertext, input_bytes plaintext)
{
  return _protect(key_id, ciphertext, plaintext);
}

output_bytes
Context::unprotect(output_bytes plaintext, input_bytes ciphertext)
{
  return _unprotect(plaintext, ciphertext);
}

SFrame::KeyState&
Context::get_state(KeyID key_id)
{
  auto it = state.find(key_id);
  if (it == state.end()) {
    throw std::runtime_error("Unknown key");
  }

  return it->second;
}

///
/// MLSContext
///

MLSContext::MLSContext(CipherSuite suite_in, size_t epoch_bits_in)
  : SFrame(suite_in)
  , epoch_bits(epoch_bits_in)
  , epoch_mask((1 << epoch_bits_in) - 1)
  , epoch_cache(1 << epoch_bits_in, std::nullopt)
{}

void
MLSContext::add_epoch(EpochID epoch_id, const bytes& sframe_epoch_secret)
{
  auto epoch_index = epoch_id & epoch_mask;
  epoch_cache.at(epoch_index).emplace(sframe_epoch_secret);
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
MLSContext::unprotect(output_bytes plaintext, input_bytes ciphertext)
{
  return _unprotect(plaintext, ciphertext);
}

MLSContext::EpochKeys::EpochKeys(bytes sframe_epoch_secret_in)
  : sframe_epoch_secret(std::move(sframe_epoch_secret_in))
{}

SFrame::KeyState&
MLSContext::EpochKeys::get(CipherSuite suite, SenderID sender_id)
{
  auto it = sender_keys.find(sender_id);
  if (it != sender_keys.end()) {
    return it->second;
  }

  auto hash_size = cipher_digest_size(suite);
  auto enc_sender_id = bytes(4);
  encode_uint(sender_id, enc_sender_id);

  auto sender_base_key =
    hkdf_expand(suite, sframe_epoch_secret, enc_sender_id, hash_size);
  auto key_state = KeyState::from_base_key(suite, sender_base_key);
  sender_keys.insert({ sender_id, std::move(key_state) });

  return sender_keys.at(sender_id);
}

SFrame::KeyState&
MLSContext::get_state(KeyID key_id)
{
  const auto epoch_index = EpochID(key_id & epoch_mask);
  const auto sender_id = SenderID(key_id >> epoch_bits);

  auto& epoch = epoch_cache.at(epoch_index);
  if (!epoch.has_value()) {
    throw std::runtime_error("Unknown epoch");
  }

  return epoch->get(suite, sender_id);
}

} // namespace sframe
