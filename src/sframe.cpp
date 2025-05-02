#include <sframe/sframe.h>

#include "crypto.h"
#include "header.h"

namespace sframe {

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
/// KeyRecord
///

static auto
from_ascii(const char* str, size_t len)
{
  const auto ptr = reinterpret_cast<const uint8_t*>(str);
  return input_bytes(ptr, len);
}

static const auto base_label = from_ascii("SFrame 1.0 Secret ", 18);
static const auto key_label = from_ascii("key ", 4);
static const auto salt_label = from_ascii("salt ", 5);

static owned_bytes<32>
sframe_key_label(CipherSuite suite, KeyID key_id)
{
  auto label = owned_bytes<32>(base_label);
  label.append(key_label);
  label.resize(32);

  auto label_data = output_bytes(label);
  encode_uint(key_id, label_data.subspan(22).first(8));
  encode_uint(static_cast<uint64_t>(suite), label_data.subspan(30));

  return label;
}

static owned_bytes<33>
sframe_salt_label(CipherSuite suite, KeyID key_id)
{
  auto label = owned_bytes<33>(base_label);
  label.append(salt_label);
  label.resize(33);

  auto label_data = output_bytes(label);
  encode_uint(key_id, label_data.last(10).first(8));
  encode_uint(static_cast<uint64_t>(suite), label_data.last(2));

  return label;
}

KeyRecord
KeyRecord::from_base_key(CipherSuite suite,
                         KeyID key_id,
                         KeyUsage usage,
                         input_bytes base_key)
{
  auto key_size = cipher_key_size(suite);
  auto nonce_size = cipher_nonce_size(suite);

  const auto empty_byte_string = owned_bytes<0>();
  const auto key_label = sframe_key_label(suite, key_id);
  const auto salt_label = sframe_salt_label(suite, key_id);

  auto secret = hkdf_extract(suite, empty_byte_string, base_key);
  auto key = hkdf_expand(suite, secret, key_label, key_size);
  auto salt = hkdf_expand(suite, secret, salt_label, nonce_size);

  return KeyRecord{ key, salt, usage, 0 };
}

///
/// Context
///

Context::Context(CipherSuite suite_in)
  : suite(suite_in)
{
}

Context::~Context() = default;

void
Context::add_key(KeyID key_id, KeyUsage usage, input_bytes base_key)
{
  keys.emplace(key_id,
               KeyRecord::from_base_key(suite, key_id, usage, base_key));
}

static owned_bytes<KeyRecord::max_salt_size>
form_nonce(Counter ctr, input_bytes salt)
{
  auto nonce = owned_bytes<KeyRecord::max_salt_size>(salt);
  for (size_t i = 0; i < sizeof(ctr); i++) {
    nonce[nonce.size() - i - 1] ^= uint8_t(ctr >> (8 * i));
  }

  return nonce;
}

static constexpr auto max_aad_size =
  Header::max_size + Context::max_metadata_size;

static owned_bytes<max_aad_size>
form_aad(const Header& header, input_bytes metadata)
{
  if (metadata.size() > Context::max_metadata_size) {
    throw buffer_too_small_error("Metadata too large");
  }

  auto aad = owned_bytes<max_aad_size>(0);
  aad.append(header.encoded());
  aad.append(metadata);
  return aad;
}

output_bytes
Context::protect(KeyID key_id,
                 output_bytes ciphertext,
                 input_bytes plaintext,
                 input_bytes metadata)
{
  auto& key_record = keys.at(key_id);
  const auto counter = key_record.counter;
  key_record.counter += 1;

  const auto header = Header{ key_id, counter };
  const auto header_data = header.encoded();
  if (ciphertext.size() < header_data.size()) {
    throw buffer_too_small_error("Ciphertext too small for SFrame header");
  }

  std::copy(header_data.begin(), header_data.end(), ciphertext.begin());
  auto inner_ciphertext = ciphertext.subspan(header_data.size());
  auto final_ciphertext =
    Context::protect_inner(header, inner_ciphertext, plaintext, metadata);
  return ciphertext.first(header_data.size() + final_ciphertext.size());
}

output_bytes
Context::unprotect(output_bytes plaintext,
                   input_bytes ciphertext,
                   input_bytes metadata)
{
  const auto header = Header::parse(ciphertext);
  const auto inner_ciphertext = ciphertext.subspan(header.size());
  return Context::unprotect_inner(
    header, plaintext, inner_ciphertext, metadata);
}

output_bytes
Context::protect_inner(const Header& header,
                       output_bytes ciphertext,
                       input_bytes plaintext,
                       input_bytes metadata)
{
  if (ciphertext.size() < plaintext.size() + cipher_overhead(suite)) {
    throw buffer_too_small_error("Ciphertext too small for cipher overhead");
  }

  const auto& key_and_salt = keys.at(header.key_id);

  const auto aad = form_aad(header, metadata);
  const auto nonce = form_nonce(header.counter, key_and_salt.salt);
  return seal(suite, key_and_salt.key, nonce, ciphertext, aad, plaintext);
}

output_bytes
Context::unprotect_inner(const Header& header,
                         output_bytes plaintext,
                         input_bytes ciphertext,
                         input_bytes metadata)
{
  if (ciphertext.size() < cipher_overhead(suite)) {
    throw buffer_too_small_error("Ciphertext too small for cipher overhead");
  }

  if (plaintext.size() < ciphertext.size() - cipher_overhead(suite)) {
    throw buffer_too_small_error("Plaintext too small for decrypted value");
  }

  const auto& key_and_salt = keys.at(header.key_id);

  const auto aad = form_aad(header, metadata);
  const auto nonce = form_nonce(header.counter, key_and_salt.salt);
  return open(suite, key_and_salt.key, nonce, plaintext, aad, ciphertext);
}

///
/// MLSContext
///

MLSContext::MLSContext(CipherSuite suite_in, size_t epoch_bits_in)
  : Context(suite_in)
  , epoch_bits(epoch_bits_in)
  , epoch_mask((size_t(1) << epoch_bits_in) - 1)
{
  epoch_cache.resize(1 << epoch_bits_in);
}

void
MLSContext::add_epoch(EpochID epoch_id, input_bytes sframe_epoch_secret)
{
  add_epoch(epoch_id, sframe_epoch_secret, 0);
}

void
MLSContext::add_epoch(EpochID epoch_id,
                      input_bytes sframe_epoch_secret,
                      size_t sender_bits)
{
  auto epoch_index = epoch_id & epoch_mask;
  auto& epoch = epoch_cache[epoch_index];

  if (epoch) {
    purge_epoch(epoch->full_epoch);
  }

  epoch.emplace(epoch_id, sframe_epoch_secret, epoch_bits, sender_bits);
}

void
MLSContext::purge_before(EpochID keeper)
{
  for (auto& ptr : epoch_cache) {
    if (ptr && ptr->full_epoch < keeper) {
      purge_epoch(ptr->full_epoch);
      ptr.reset();
    }
  }
}

output_bytes
MLSContext::protect(EpochID epoch_id,
                    SenderID sender_id,
                    output_bytes ciphertext,
                    input_bytes plaintext,
                    input_bytes metadata)
{
  return protect(epoch_id, sender_id, 0, ciphertext, plaintext, metadata);
}

output_bytes
MLSContext::protect(EpochID epoch_id,
                    SenderID sender_id,
                    ContextID context_id,
                    output_bytes ciphertext,
                    input_bytes plaintext,
                    input_bytes metadata)
{
  auto key_id = form_key_id(epoch_id, sender_id, context_id);
  ensure_key(key_id, KeyUsage::protect);
  return Context::protect(key_id, ciphertext, plaintext, metadata);
}

output_bytes
MLSContext::unprotect(output_bytes plaintext,
                      input_bytes ciphertext,
                      input_bytes metadata)
{
  const auto header = Header::parse(ciphertext);
  const auto inner_ciphertext = ciphertext.subspan(header.size());

  ensure_key(header.key_id, KeyUsage::unprotect);
  return Context::unprotect_inner(
    header, plaintext, inner_ciphertext, metadata);
}

MLSContext::EpochKeys::EpochKeys(MLSContext::EpochID full_epoch_in,
                                 input_bytes sframe_epoch_secret_in,
                                 size_t epoch_bits,
                                 size_t sender_bits_in)
  : full_epoch(full_epoch_in)
  , sframe_epoch_secret(sframe_epoch_secret_in)
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
  max_sender_id = (one << sender_bits) - 1;
  max_context_id = (one << context_bits) - 1;
}

owned_bytes<MLSContext::EpochKeys::max_secret_size>
MLSContext::EpochKeys::base_key(CipherSuite ciphersuite,
                                SenderID sender_id) const
{
  const auto hash_size = cipher_digest_size(ciphersuite);
  auto enc_sender_id = owned_bytes<8>();
  encode_uint(sender_id, enc_sender_id);

  return hkdf_expand(
    ciphersuite, sframe_epoch_secret, enc_sender_id, hash_size);
}

void
MLSContext::purge_epoch(EpochID epoch_id)
{
  const auto drop_bits = epoch_id & epoch_bits;

  keys.erase_if_key(
    [&](const auto& epoch) { return (epoch & epoch_bits) == drop_bits; });
}

KeyID
MLSContext::form_key_id(EpochID epoch_id,
                        SenderID sender_id,
                        ContextID context_id) const
{
  auto epoch_index = epoch_id & epoch_mask;
  auto& epoch = epoch_cache[epoch_index];
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
MLSContext::ensure_key(KeyID key_id, KeyUsage usage)
{
  // If the required key already exists, we are done
  const auto epoch_index = key_id & epoch_mask;
  auto& epoch = epoch_cache[epoch_index];
  if (!epoch) {
    throw invalid_parameter_error("Unknown epoch: " +
                                  std::to_string(epoch_index));
  }

  if (keys.contains(key_id)) {
    return;
  }

  // Otherwise, derive a key and implant it
  const auto sender_id = key_id >> epoch_bits;
  Context::add_key(key_id, usage, epoch->base_key(suite, sender_id));
  return;
}

} // namespace sframe
