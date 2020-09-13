#include <sframe/sframe.h>

#include "crypto.h"

#include <openssl/err.h>
#include <openssl/evp.h>

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

Context::Context(CipherSuite suite_in)
  : suite(suite_in)
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

void
Context::add_key(KeyID key_id, const bytes& base_key)
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

  state.insert_or_assign(key_id,
                         KeyState{ std::move(key), std::move(salt), 0 });
}

static size_t
encode_uint(uint64_t val, output_bytes start)
{
  size_t size = 1;
  while (val >> (8 * size) > 0) {
    size += 1;
  }

  for (size_t i = 0; i < size; i++) {
    start[size - i - 1] = uint8_t(val >> (8 * i));
  }

  return size;
}

static uint64_t
decode_uint(input_bytes data)
{
  uint64_t val = 0;
  for (size_t i = 0; i < data.size(); i++) {
    val = (val << 8) + static_cast<uint64_t>(data[i]);
  }
  return val;
}

static bytes
form_nonce(CipherSuite suite, Counter ctr, const bytes& salt)
{
  auto nonce_size = cipher_nonce_size(suite);
  auto nonce = bytes(nonce_size);
  for (size_t i = 0; i < sizeof(ctr); i++) {
    nonce[nonce_size - i - 1] = uint8_t(ctr >> (8 * i));
  }

  for (size_t i = 0; i < nonce.size(); i++) {
    nonce[i] ^= salt[i];
  }

  return nonce;
}

static constexpr size_t min_header_size = 1;
static constexpr size_t max_header_size = 1 + 8 + 8;

static size_t
encode_header(KeyID kid, Counter ctr, output_bytes data)
{
  size_t kid_size = 0;
  if (kid > 0x07) {
    kid_size = encode_uint(kid, data.subspan(1));
  }

  size_t ctr_size = encode_uint(ctr, data.subspan(1 + kid_size));
  if ((ctr_size > 0x07) || (kid_size > 0x07)) {
    throw std::runtime_error("Header overflow");
  }

  data[0] = uint8_t(ctr_size << 4);
  if (kid <= 0x07) {
    data[0] |= kid;
  } else {
    data[0] |= 0x08 | kid_size;
  }

  return 1 + kid_size + ctr_size;
}

static std::tuple<KeyID, Counter, input_bytes>
decode_header(input_bytes data)
{
  if (data.size() < min_header_size) {
    throw std::runtime_error("Ciphertext too small to decode header");
  }

  auto cfg = data[0];
  auto ctr_size = size_t((cfg >> 4) & 0x07);
  auto kid_long = (cfg & 0x08) > 0;
  auto kid_size = size_t(cfg & 0x07);

  auto kid = KeyID(kid_size);
  if (kid_long) {
    if (data.size() < 1 + kid_size) {
      throw std::runtime_error("Ciphertext too small to decode KID");
    }

    kid = KeyID(decode_uint(data.subspan(1, kid_size)));
  } else {
    kid_size = 0;
  }

  if (data.size() < 1 + kid_size + ctr_size) {
    throw std::runtime_error("Ciphertext too small to decode CTR");
  }
  auto ctr = Counter(decode_uint(data.subspan(1 + kid_size, ctr_size)));

  return std::make_tuple(kid, ctr, data.subspan(0, 1 + kid_size + ctr_size));
}

output_bytes
Context::protect(KeyID key_id, output_bytes ciphertext, input_bytes plaintext)
{
  auto it = state.find(key_id);
  if (it == state.end()) {
    throw std::runtime_error("Unknown key");
  }

  auto& st = it->second;
  const auto ctr = st.counter;
  st.counter += 1;

  if (ciphertext.size() < max_header_size) {
    throw std::runtime_error("Ciphertext to small to encod header");
  }

  auto hdr_size = encode_header(key_id, ctr, ciphertext);
  auto header = ciphertext.subspan(0, hdr_size);
  auto inner_ciphertext = ciphertext.subspan(hdr_size);

  const auto nonce = form_nonce(suite, ctr, st.salt);
  auto final_ciphertext =
    seal(suite, st.key, nonce, inner_ciphertext, header, plaintext);
  return ciphertext.subspan(0, hdr_size + final_ciphertext.size());
}

output_bytes
Context::unprotect(output_bytes plaintext, input_bytes ciphertext)
{
  auto [kid, ctr, header] = decode_header(ciphertext);
  auto inner_ciphertext = ciphertext.subspan(header.size());

  auto it = state.find(kid);
  if (it == state.end()) {
    throw std::runtime_error("Unknown key");
  }

  const auto& st = it->second;
  const auto nonce = form_nonce(suite, ctr, st.salt);
  return open(suite, st.key, nonce, plaintext, header, inner_ciphertext);
}

} // namespace sframe
