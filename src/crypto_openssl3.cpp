#if defined(OPENSSL_3)

#include "crypto.h"
#include "header.h"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

namespace sframe {

///
/// Convert between native identifiers / errors and OpenSSL ones
///

openssl_error::openssl_error()
  : std::runtime_error(ERR_error_string(ERR_get_error(), nullptr))
{
}

static const EVP_CIPHER*
openssl_cipher(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_CM_128_HMAC_SHA256_8:
    case CipherSuite::AES_CM_128_HMAC_SHA256_4:
      return EVP_aes_128_ctr();

    case CipherSuite::AES_GCM_128_SHA256:
      return EVP_aes_128_gcm();

    case CipherSuite::AES_GCM_256_SHA512:
      return EVP_aes_256_gcm();

    default:
      throw unsupported_ciphersuite_error();
  }
}

static const char*
openssl_digest_name(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_CM_128_HMAC_SHA256_8:
    case CipherSuite::AES_CM_128_HMAC_SHA256_4:
    case CipherSuite::AES_GCM_128_SHA256:
      return OSSL_DIGEST_NAME_SHA2_256;

    case CipherSuite::AES_GCM_256_SHA512:
      return OSSL_DIGEST_NAME_SHA2_512;

    default:
      throw unsupported_ciphersuite_error();
  }
}

///
/// HKDF
///

using scoped_evp_kdf = std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)>;
using scoped_evp_kdf_ctx =
  std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)>;

bytes
hkdf_extract(CipherSuite suite, const bytes& salt, const bytes& ikm)
{
  auto mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
  auto digest_name = const_cast<char*>(openssl_digest_name(suite));
  auto* salt_ptr =
    const_cast<void*>(reinterpret_cast<const void*>(salt.data()));
  auto* ikm_ptr = const_cast<void*>(reinterpret_cast<const void*>(ikm.data()));

  const auto params = std::array<OSSL_PARAM, 5>{
    OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
    OSSL_PARAM_construct_utf8_string(
      OSSL_KDF_PARAM_DIGEST, digest_name, 0),
    OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ikm_ptr, ikm.size()),
    OSSL_PARAM_construct_octet_string(
      OSSL_KDF_PARAM_SALT, salt_ptr, salt.size()),
    OSSL_PARAM_construct_end(),
  };

  const auto kdf =
    scoped_evp_kdf(EVP_KDF_fetch(NULL, "HKDF", NULL), EVP_KDF_free);
  const auto ctx =
    scoped_evp_kdf_ctx(EVP_KDF_CTX_new(kdf.get()), EVP_KDF_CTX_free);
  if (1 != EVP_KDF_CTX_set_params(ctx.get(), params.data())) {
    throw openssl_error();
  }

  const auto digest_size = EVP_KDF_CTX_get_kdf_size(ctx.get());
  auto out = bytes(digest_size);
  if (1 != EVP_KDF_derive(ctx.get(), out.data(), out.size(), nullptr)) {
    throw openssl_error();
  }

  return out;
}

bytes
hkdf_expand(CipherSuite suite, const bytes& prk, const bytes& info, size_t size)
{
  auto mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
  auto digest_name = const_cast<char*>(openssl_digest_name(suite));
  auto* prk_ptr = const_cast<void*>(reinterpret_cast<const void*>(prk.data()));
  auto* info_ptr =
    const_cast<void*>(reinterpret_cast<const void*>(info.data()));

  const auto params = std::array<OSSL_PARAM, 5>{
    OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
    OSSL_PARAM_construct_utf8_string(
      OSSL_KDF_PARAM_DIGEST, digest_name, 0),
    OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, prk_ptr, prk.size()),
    OSSL_PARAM_construct_octet_string(
      OSSL_KDF_PARAM_INFO, info_ptr, info.size()),
    OSSL_PARAM_construct_end(),
  };

  const auto kdf =
    scoped_evp_kdf(EVP_KDF_fetch(NULL, "HKDF", NULL), EVP_KDF_free);
  const auto ctx =
    scoped_evp_kdf_ctx(EVP_KDF_CTX_new(kdf.get()), EVP_KDF_CTX_free);

  auto out = bytes(size);
  if (1 != EVP_KDF_derive(ctx.get(), out.data(), out.size(), params.data())) {
    throw openssl_error();
  }

  return out;
}

///
/// AEAD Algorithms
///

static bytes
compute_tag(CipherSuite suite,
            input_bytes auth_key,
            input_bytes aad,
            input_bytes ct,
            size_t tag_size)
{
  using scoped_evp_mac = std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)>;
  using scoped_evp_mac_ctx =
    std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)>;

  auto digest_name = const_cast<char*>(openssl_digest_name(suite));
  std::array<OSSL_PARAM, 2> params = {
    OSSL_PARAM_construct_utf8_string(
      OSSL_ALG_PARAM_DIGEST, digest_name, 0),
    OSSL_PARAM_construct_end()
  };

  const auto mac = scoped_evp_mac(
    EVP_MAC_fetch(nullptr, OSSL_MAC_NAME_HMAC, nullptr), EVP_MAC_free);
  const auto ctx =
    scoped_evp_mac_ctx(EVP_MAC_CTX_new(mac.get()), EVP_MAC_CTX_free);

  if (1 != EVP_MAC_init(
             ctx.get(), auth_key.data(), auth_key.size(), params.data())) {
    throw openssl_error();
  }

  if (1 != EVP_MAC_update(ctx.get(), aad.data(), aad.size())) {
    throw openssl_error();
  }

  if (1 != EVP_MAC_update(ctx.get(), ct.data(), ct.size())) {
    throw openssl_error();
  }

  size_t size = 0;
  auto tag = bytes(cipher_digest_size(suite));
  if (1 != EVP_MAC_final(ctx.get(), tag.data(), &size, tag.size())) {
    throw openssl_error();
  }

  tag.resize(tag_size);
  return tag;
}

using scoped_evp_cipher_ctx =
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

static void
ctr_crypt(CipherSuite suite,
          input_bytes key,
          input_bytes nonce,
          output_bytes out,
          input_bytes in)
{
  if (out.size() != in.size()) {
    throw buffer_too_small_error("CTR size mismatch");
  }

  auto ctx = scoped_evp_cipher_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (ctx.get() == nullptr) {
    throw openssl_error();
  }

  auto padded_nonce = bytes(nonce.begin(), nonce.end());
  padded_nonce.resize(16);

  auto cipher = openssl_cipher(suite);
  if (1 !=
      EVP_EncryptInit(ctx.get(), cipher, key.data(), padded_nonce.data())) {
    throw openssl_error();
  }

  int outlen = 0;
  auto in_size_int = static_cast<int>(in.size());
  if (1 != EVP_EncryptUpdate(
             ctx.get(), out.data(), &outlen, in.data(), in_size_int)) {
    throw openssl_error();
  }

  if (1 != EVP_EncryptFinal(ctx.get(), nullptr, &outlen)) {
    throw openssl_error();
  }
}

static output_bytes
seal_ctr(CipherSuite suite,
         input_bytes key,
         input_bytes nonce,
         output_bytes ct,
         input_bytes aad,
         input_bytes pt)
{
  auto tag_size = cipher_overhead(suite);
  if (ct.size() < pt.size() + tag_size) {
    throw buffer_too_small_error("Ciphertext buffer too small");
  }

  // Split the key into enc and auth subkeys
  auto enc_key_size = cipher_key_size(suite);
  auto enc_key = key.first(enc_key_size);
  auto auth_key = key.subspan(enc_key_size);

  // Encrypt with AES-CM
  auto inner_ct = ct.subspan(0, pt.size());
  ctr_crypt(suite, enc_key, nonce, inner_ct, pt);

  // Authenticate with truncated HMAC
  auto mac = compute_tag(suite, auth_key, aad, inner_ct, tag_size);
  auto tag = ct.subspan(pt.size(), tag_size);
  std::copy(mac.begin(), mac.begin() + tag_size, tag.begin());

  return ct.subspan(0, pt.size() + tag_size);
}

static output_bytes
seal_aead(CipherSuite suite,
          input_bytes key,
          input_bytes nonce,
          output_bytes ct,
          input_bytes aad,
          input_bytes pt)
{
  auto tag_size = cipher_overhead(suite);
  if (ct.size() < pt.size() + tag_size) {
    throw buffer_too_small_error("Ciphertext buffer too small");
  }

  auto ctx = scoped_evp_cipher_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (ctx.get() == nullptr) {
    throw openssl_error();
  }

  auto cipher = openssl_cipher(suite);
  if (1 != EVP_EncryptInit(ctx.get(), cipher, key.data(), nonce.data())) {
    throw openssl_error();
  }

  int outlen = 0;
  auto aad_size_int = static_cast<int>(aad.size());
  if (aad.size() > 0) {
    if (1 != EVP_EncryptUpdate(
               ctx.get(), nullptr, &outlen, aad.data(), aad_size_int)) {
      throw openssl_error();
    }
  }

  auto pt_size_int = static_cast<int>(pt.size());
  if (1 != EVP_EncryptUpdate(
             ctx.get(), ct.data(), &outlen, pt.data(), pt_size_int)) {
    throw openssl_error();
  }

  // Providing nullptr as an argument is safe here because this
  // function never writes with GCM; it only computes the tag
  if (1 != EVP_EncryptFinal(ctx.get(), nullptr, &outlen)) {
    throw openssl_error();
  }

  auto tag = ct.subspan(pt.size(), tag_size);
  auto tag_ptr = const_cast<void*>(static_cast<const void*>(tag.data()));
  auto tag_size_downcast = static_cast<int>(tag.size());
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx.get(), EVP_CTRL_GCM_GET_TAG, tag_size_downcast, tag_ptr)) {
    throw openssl_error();
  }

  return ct.subspan(0, pt.size() + tag_size);
}

output_bytes
seal(CipherSuite suite,
     const bytes& key,
     const bytes& nonce,
     output_bytes ct,
     input_bytes aad,
     input_bytes pt)
{
  switch (suite) {
    case CipherSuite::AES_CM_128_HMAC_SHA256_8:
    case CipherSuite::AES_CM_128_HMAC_SHA256_4: {
      return seal_ctr(suite, key, nonce, ct, aad, pt);
    }

    case CipherSuite::AES_GCM_128_SHA256:
    case CipherSuite::AES_GCM_256_SHA512: {
      return seal_aead(suite, key, nonce, ct, aad, pt);
    }
  }

  throw unsupported_ciphersuite_error();
}

static output_bytes
open_ctr(CipherSuite suite,
         input_bytes key,
         input_bytes nonce,
         output_bytes pt,
         input_bytes aad,
         input_bytes ct)
{
  auto tag_size = cipher_overhead(suite);
  if (ct.size() < tag_size) {
    throw buffer_too_small_error("Ciphertext buffer too small");
  }

  auto inner_ct_size = ct.size() - tag_size;
  auto inner_ct = ct.subspan(0, inner_ct_size);
  auto tag = ct.subspan(inner_ct_size, tag_size);

  // Split the key into enc and auth subkeys
  auto enc_key_size = cipher_key_size(suite);
  auto enc_key = key.first(enc_key_size);
  auto auth_key = key.subspan(enc_key_size);

  // Authenticate with truncated HMAC
  auto mac = compute_tag(suite, auth_key, aad, inner_ct, tag_size);
  if (CRYPTO_memcmp(mac.data(), tag.data(), tag.size()) != 0) {
    throw authentication_error();
  }

  // Decrypt with AES-CTR
  const auto pt_out = pt.first(inner_ct_size);
  ctr_crypt(suite, enc_key, nonce, pt_out, ct.first(inner_ct_size));

  return pt_out;
}

static output_bytes
open_aead(CipherSuite suite,
          input_bytes key,
          input_bytes nonce,
          output_bytes pt,
          input_bytes aad,
          input_bytes ct)
{
  auto tag_size = cipher_overhead(suite);
  if (ct.size() < tag_size) {
    throw buffer_too_small_error("Ciphertext buffer too small");
  }

  auto inner_ct_size = ct.size() - tag_size;
  if (pt.size() < inner_ct_size) {
    throw buffer_too_small_error("Plaintext buffer too small");
  }

  auto ctx = scoped_evp_cipher_ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
  if (ctx.get() == nullptr) {
    throw openssl_error();
  }

  auto cipher = openssl_cipher(suite);
  if (1 != EVP_DecryptInit(ctx.get(), cipher, key.data(), nonce.data())) {
    throw openssl_error();
  }

  auto tag = ct.subspan(inner_ct_size, tag_size);
  auto tag_ptr = const_cast<void*>(static_cast<const void*>(tag.data()));
  auto tag_size_downcast = static_cast<int>(tag.size());
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx.get(), EVP_CTRL_GCM_SET_TAG, tag_size_downcast, tag_ptr)) {
    throw openssl_error();
  }

  int out_size;
  auto aad_size_int = static_cast<int>(aad.size());
  if (aad.size() > 0) {
    if (1 != EVP_DecryptUpdate(
               ctx.get(), nullptr, &out_size, aad.data(), aad_size_int)) {
      throw openssl_error();
    }
  }

  auto inner_ct_size_int = static_cast<int>(inner_ct_size);
  if (1 != EVP_DecryptUpdate(
             ctx.get(), pt.data(), &out_size, ct.data(), inner_ct_size_int)) {
    throw openssl_error();
  }

  // Providing nullptr as an argument is safe here because this
  // function never writes with GCM; it only verifies the tag
  if (1 != EVP_DecryptFinal(ctx.get(), nullptr, &out_size)) {
    throw authentication_error();
  }

  return pt.subspan(0, inner_ct_size);
}

output_bytes
open(CipherSuite suite,
     const bytes& key,
     const bytes& nonce,
     output_bytes pt,
     input_bytes aad,
     input_bytes ct)
{
  switch (suite) {
    case CipherSuite::AES_CM_128_HMAC_SHA256_8:
    case CipherSuite::AES_CM_128_HMAC_SHA256_4: {
      return open_ctr(suite, key, nonce, pt, aad, ct);
    }

    case CipherSuite::AES_GCM_128_SHA256:
    case CipherSuite::AES_GCM_256_SHA512: {
      return open_aead(suite, key, nonce, pt, aad, ct);
    }
  }

  throw unsupported_ciphersuite_error();
}

} // namespace sframe

#endif // defined(OPENSSL_3)
