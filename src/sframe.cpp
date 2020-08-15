#include <openssl/err.h>      // for ERR_error_string, ERR_get_error
#include <openssl/evp.h>      // for EVP_CIPHER_CTX_ctrl, EVP_CIPHER_CTX_new
#include <openssl/ossl_typ.h> // for EVP_CIPHER_CTX, EVP_CIPHER
#include <sframe/sframe.h>
#include <stddef.h> // for size_t
#include <stdint.h> // for uint8_t, uint64_t

#include <iomanip>     // for operator<<, setfill, setw
#include <iostream>    // for ostream, basic_ostream, ios
#include <map>         // for __map_iterator, operator==, map
#include <memory>      // for unique_ptr
#include <stdexcept>   // for runtime_error
#include <tuple>       // for make_tuple, tuple
#include <type_traits> // for move
#include <utility>     // for pair
#include <vector>      // for vector

namespace sframe {

std::ostream&
operator<<(std::ostream& str, const bytes& data)
{
  str.flags(std::ios::hex);
  for (const auto& byte : data) {
    str << std::setw(2) << std::setfill('0') << int(byte);
  }
  return str;
}

static auto evp_cipher_ctx_free = [](EVP_CIPHER_CTX* ptr) {
  EVP_CIPHER_CTX_free(ptr);
};

using scoped_evp_ctx =
  std::unique_ptr<EVP_CIPHER_CTX, decltype(evp_cipher_ctx_free)>;

static std::runtime_error
openssl_error()
{
  auto code = ERR_get_error();
  return std::runtime_error(ERR_error_string(code, nullptr));
}

static const EVP_CIPHER*
openssl_cipher(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_GCM_128:
      return EVP_aes_128_gcm();

    case CipherSuite::AES_GCM_256:
      return EVP_aes_256_gcm();

    default:
      throw std::runtime_error("Unsupported ciphersuite");
  }
}

static int
openssl_tag_size(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_GCM_128:
    case CipherSuite::AES_GCM_256:
      return 16;

    default:
      throw std::runtime_error("Unsupported ciphersuite");
  }
}

static size_t
openssl_nonce_size(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_GCM_128:
    case CipherSuite::AES_GCM_256:
      return 12;

    default:
      throw std::runtime_error("Unsupported ciphersuite");
  }
}

static size_t
seal(CipherSuite suite,
     const bytes& key,
     const bytes& nonce,
     size_t aad_size,
     uint8_t* ct,
     size_t ct_size,
     const uint8_t* pt,
     size_t pt_size)
{
  auto tag_size = openssl_tag_size(suite);
  if (ct_size < aad_size + pt_size + tag_size) {
    throw std::runtime_error("Ciphertext buffer too small ");
  }

  auto ctx = scoped_evp_ctx(EVP_CIPHER_CTX_new(), evp_cipher_ctx_free);
  if (ctx.get() == nullptr) {
    throw openssl_error();
  }

  auto cipher = openssl_cipher(suite);
  if (1 != EVP_EncryptInit(ctx.get(), cipher, key.data(), nonce.data())) {
    throw openssl_error();
  }

  int outlen = 0;
  auto aad_size_int = static_cast<int>(aad_size);
  if (aad_size > 0) {
    if (1 != EVP_EncryptUpdate(ctx.get(), nullptr, &outlen, ct, aad_size_int)) {
      throw openssl_error();
    }
  }

  auto pt_size_int = static_cast<int>(pt_size);
  if (1 !=
      EVP_EncryptUpdate(ctx.get(), ct + aad_size, &outlen, pt, pt_size_int)) {
    throw openssl_error();
  }

  auto inner_ct_size = size_t(outlen);
  auto tag_start = ct + aad_size + inner_ct_size;

  // Providing nullptr as an argument is safe here because this
  // function never writes with GCM; it only computes the tag
  if (1 != EVP_EncryptFinal(ctx.get(), nullptr, &outlen)) {
    throw openssl_error();
  }

  auto tag_ptr = const_cast<void*>(static_cast<const void*>(tag_start));
  if (1 !=
      EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, tag_size, tag_ptr)) {
    throw openssl_error();
  }

  return aad_size + pt_size + tag_size;
}

static size_t
open(CipherSuite suite,
     const bytes& key,
     const bytes& nonce,
     size_t aad_size,
     uint8_t* pt,
     size_t pt_size,
     const uint8_t* ct,
     size_t ct_size)
{
  auto tag_size = openssl_tag_size(suite);
  if (ct_size < aad_size + tag_size) {
    throw std::runtime_error("Ciphertext buffer too small");
  }

  auto inner_ct_size = ct_size - aad_size - tag_size;
  if (pt_size < inner_ct_size) {
    throw std::runtime_error("Plaintext buffer too small");
  }

  auto aad_start = ct;
  auto ct_start = aad_start + aad_size;
  auto tag_start = ct_start + inner_ct_size;

  auto ctx = scoped_evp_ctx(EVP_CIPHER_CTX_new(), evp_cipher_ctx_free);
  if (ctx.get() == nullptr) {
    throw openssl_error();
  }

  auto cipher = openssl_cipher(suite);
  if (1 != EVP_DecryptInit(ctx.get(), cipher, key.data(), nonce.data())) {
    throw openssl_error();
  }

  auto tag = bytes(tag_start, tag_start + tag_size);
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx.get(), EVP_CTRL_GCM_SET_TAG, tag_size, tag.data())) {
    throw openssl_error();
  }

  int out_size;
  auto aad_size_int = static_cast<int>(aad_size);
  if (aad_size > 0) {
    if (1 != EVP_DecryptUpdate(
               ctx.get(), nullptr, &out_size, aad_start, aad_size_int)) {
      throw openssl_error();
    }
  }

  auto inner_ct_size_int = static_cast<int>(inner_ct_size);
  if (1 != EVP_DecryptUpdate(
             ctx.get(), pt, &out_size, ct_start, inner_ct_size_int)) {
    throw openssl_error();
  }

  // Providing nullptr as an argument is safe here because this
  // function never writes with GCM; it only verifies the tag
  if (1 != EVP_DecryptFinal(ctx.get(), nullptr, &out_size)) {
    throw std::runtime_error("AEAD authentication failure");
  }

  return inner_ct_size;
}

Context::Context(CipherSuite suite_in)
  : suite(suite_in)
{}

void
Context::add_key(KeyID key_id, bytes key)
{
  state.insert_or_assign(key_id, KeyState{ std::move(key), 0 });
}

static size_t
encode_uint(uint64_t val, uint8_t* start)
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
decode_uint(const uint8_t* data, size_t size)
{
  uint64_t val = 0;
  for (size_t i = 0; i < size; i++) {
    val = (val << 8) + data[size - i - 1];
  }
  return val;
}

static bytes
form_nonce(CipherSuite suite, Counter ctr)
{
  auto nonce_size = openssl_nonce_size(suite);
  auto nonce = bytes(nonce_size);
  for (size_t i = 0; i < sizeof(ctr); i++) {
    nonce[nonce_size - i - 1] = uint8_t(ctr >> (8 * i));
  }
  return nonce;
}

static constexpr size_t min_header_size = 1;
static constexpr size_t max_header_size = 1 + 8 + 8;

static size_t
encode_header(KeyID kid, Counter ctr, uint8_t* data)
{
  size_t kid_size = 0;
  if (kid > 0x07) {
    kid_size = encode_uint(kid, data + 1);
  }

  size_t ctr_size = encode_uint(ctr, data + 1 + kid_size);
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

static std::tuple<KeyID, Counter, size_t>
decode_header(const uint8_t* data, size_t size)
{
  if (size < min_header_size) {
    throw std::runtime_error("Ciphertext too small to decode header");
  }

  auto cfg = data[0];
  auto ctr_size = size_t((cfg >> 4) & 0x07);
  auto kid_long = (cfg & 0x08) > 0;
  auto kid_size = size_t(cfg & 0x07);

  auto kid = KeyID(kid_size);
  if (kid_long) {
    if (size < 1 + kid_size) {
      throw std::runtime_error("Ciphertext too small to decode KID");
    }

    kid = KeyID(decode_uint(data + 1, kid_size));
  } else {
    kid_size = 0;
  }

  if (size < 1 + kid_size + ctr_size) {
    throw std::runtime_error("Ciphertext too small to decode CTR");
  }
  auto ctr = Counter(decode_uint(data + 1 + kid_size, ctr_size));

  return std::make_tuple(kid, ctr, 1 + kid_size + ctr_size);
}

bytes
Context::protect(KeyID kid, const bytes& plaintext)
{
  auto it = state.find(kid);
  if (it == state.end()) {
    throw std::runtime_error("Unknown key");
  }

  const auto& key = it->second.key;
  const auto ctr = it->second.counter;
  it->second.counter += 1;

  auto ct = bytes(max_header_size);
  auto hdr_size = encode_header(kid, ctr, ct.data());
  auto tag_size = openssl_tag_size(suite);
  ct.resize(hdr_size + plaintext.size() + tag_size);

  const auto nonce = form_nonce(suite, ctr);
  seal(suite,
       key,
       nonce,
       hdr_size,
       ct.data(),
       ct.size(),
       plaintext.data(),
       plaintext.size());
  return ct;
}

bytes
Context::unprotect(const bytes& ciphertext)
{
  auto [kid, ctr, hdr_size] =
    decode_header(ciphertext.data(), ciphertext.size());
  auto tag_size = openssl_tag_size(suite);
  if (ciphertext.size() < hdr_size + tag_size) {
    throw std::runtime_error("Ciphertext too small");
  }

  auto it = state.find(kid);
  if (it == state.end()) {
    throw std::runtime_error("Unknown key");
  }

  const auto& key = it->second.key;
  const auto nonce = form_nonce(suite, ctr);
  auto pt = bytes(ciphertext.size() - hdr_size - tag_size);
  open(suite,
       key,
       nonce,
       hdr_size,
       pt.data(),
       pt.size(),
       ciphertext.data(),
       ciphertext.size());
  return pt;
}

} // namespace sframe
