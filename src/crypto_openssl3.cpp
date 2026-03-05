#if defined(OPENSSL_3)

#include "crypto.h"
#include "header.h"

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

namespace SFRAME_NAMESPACE {

///
/// Scoped pointers for OpenSSL objects
///

using scoped_evp_cipher_ctx =
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

///
/// Convert between native identifiers / errors and OpenSSL ones
///

crypto_error::crypto_error()
  : std::runtime_error(ERR_error_string(ERR_get_error(), nullptr))
{
}

static const EVP_CIPHER*
openssl_cipher(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32:
      return EVP_aes_128_ctr();

    case CipherSuite::AES_GCM_128_SHA256:
      return EVP_aes_128_gcm();

    case CipherSuite::AES_GCM_256_SHA512:
      return EVP_aes_256_gcm();

    default:
      throw unsupported_ciphersuite_error();
  }
}

static std::string
openssl_digest_name(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32:
    case CipherSuite::AES_GCM_128_SHA256:
      return OSSL_DIGEST_NAME_SHA2_256;

    case CipherSuite::AES_GCM_256_SHA512:
      return OSSL_DIGEST_NAME_SHA2_512;

    default:
      throw unsupported_ciphersuite_error();
  }
}

static bool
is_ctr_hmac_suite(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32:
      return true;
    default:
      return false;
  }
}

///
/// CipherHandle and HmacHandle definitions
///

struct CipherHandle
{
  scoped_evp_cipher_ctx ctx;
  CipherHandle()
    : ctx(nullptr, EVP_CIPHER_CTX_free)
  {
  }
};

// HmacHandle for OpenSSL 3.x holds both the MAC algorithm and context
struct HmacHandle
{
  std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)> mac;
  std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> ctx;

  HmacHandle()
    : mac(nullptr, EVP_MAC_free)
    , ctx(nullptr, EVP_MAC_CTX_free)
  {
  }
};

void
CipherState::Deleter::operator()(CipherHandle* h) const
{
  delete h;
}

void
CipherState::Deleter::operator()(HmacHandle* h) const
{
  delete h;
}

CipherState::CipherState(CipherHandle* cipher,
                         HmacHandle* hmac,
                         CipherSuite suite_in)
  : cipher_handle(cipher)
  , hmac_handle(hmac)
  , suite(suite_in)
{
}

CipherState
CipherState::create_seal(CipherSuite suite, input_bytes key)
{
  auto cipher_h = std::make_unique<CipherHandle>();
  cipher_h->ctx.reset(EVP_CIPHER_CTX_new());
  if (cipher_h->ctx == nullptr) {
    throw crypto_error();
  }

  auto cipher = openssl_cipher(suite);
  std::unique_ptr<HmacHandle> hmac_h;

  if (is_ctr_hmac_suite(suite)) {
    // CTR+HMAC: key is split into enc_key and auth_key
    auto enc_key_size = cipher_enc_key_size(suite);
    auto enc_key = key.first(enc_key_size);
    auto auth_key = key.subspan(enc_key_size);

    // Initialize AES-CTR context (always encrypt for CTR mode)
    if (1 != EVP_EncryptInit_ex(
               cipher_h->ctx.get(), cipher, nullptr, enc_key.data(), nullptr)) {
      throw crypto_error();
    }

    // Initialize HMAC
    hmac_h = std::make_unique<HmacHandle>();
    hmac_h->mac.reset(EVP_MAC_fetch(nullptr, OSSL_MAC_NAME_HMAC, nullptr));
    if (hmac_h->mac == nullptr) {
      throw crypto_error();
    }

    hmac_h->ctx.reset(EVP_MAC_CTX_new(hmac_h->mac.get()));
    if (hmac_h->ctx == nullptr) {
      throw crypto_error();
    }

    auto digest_name = openssl_digest_name(suite);
    std::array<OSSL_PARAM, 2> params = {
      OSSL_PARAM_construct_utf8_string(
        OSSL_ALG_PARAM_DIGEST, digest_name.data(), 0),
      OSSL_PARAM_construct_end()
    };

    if (1 !=
        EVP_MAC_init(
          hmac_h->ctx.get(), auth_key.data(), auth_key.size(), params.data())) {
      throw crypto_error();
    }
  } else {
    // GCM: use full key
    if (1 != EVP_EncryptInit_ex(
               cipher_h->ctx.get(), cipher, nullptr, key.data(), nullptr)) {
      throw crypto_error();
    }
  }

  return CipherState(cipher_h.release(), hmac_h.release(), suite);
}

CipherState
CipherState::create_open(CipherSuite suite, input_bytes key)
{
  auto cipher_h = std::make_unique<CipherHandle>();
  cipher_h->ctx.reset(EVP_CIPHER_CTX_new());
  if (cipher_h->ctx == nullptr) {
    throw crypto_error();
  }

  auto cipher = openssl_cipher(suite);
  std::unique_ptr<HmacHandle> hmac_h;

  if (is_ctr_hmac_suite(suite)) {
    // CTR+HMAC: key is split into enc_key and auth_key
    auto enc_key_size = cipher_enc_key_size(suite);
    auto enc_key = key.first(enc_key_size);
    auto auth_key = key.subspan(enc_key_size);

    // Initialize AES-CTR context (always encrypt for CTR mode - CTR is
    // symmetric)
    if (1 != EVP_EncryptInit_ex(
               cipher_h->ctx.get(), cipher, nullptr, enc_key.data(), nullptr)) {
      throw crypto_error();
    }

    // Initialize HMAC
    hmac_h = std::make_unique<HmacHandle>();
    hmac_h->mac.reset(EVP_MAC_fetch(nullptr, OSSL_MAC_NAME_HMAC, nullptr));
    if (hmac_h->mac == nullptr) {
      throw crypto_error();
    }

    hmac_h->ctx.reset(EVP_MAC_CTX_new(hmac_h->mac.get()));
    if (hmac_h->ctx == nullptr) {
      throw crypto_error();
    }

    auto digest_name = openssl_digest_name(suite);
    std::array<OSSL_PARAM, 2> params = {
      OSSL_PARAM_construct_utf8_string(
        OSSL_ALG_PARAM_DIGEST, digest_name.data(), 0),
      OSSL_PARAM_construct_end()
    };

    if (1 !=
        EVP_MAC_init(
          hmac_h->ctx.get(), auth_key.data(), auth_key.size(), params.data())) {
      throw crypto_error();
    }
  } else {
    // GCM: use full key
    if (1 != EVP_DecryptInit_ex(
               cipher_h->ctx.get(), cipher, nullptr, key.data(), nullptr)) {
      throw crypto_error();
    }
  }

  return CipherState(cipher_h.release(), hmac_h.release(), suite);
}

///
/// AEAD Algorithms - CTR+HMAC
///

static output_bytes
seal_ctr(EVP_CIPHER_CTX* ctx,
         EVP_MAC_CTX* hmac,
         CipherSuite suite,
         input_bytes nonce,
         output_bytes ct,
         input_bytes aad,
         input_bytes pt)
{
  auto tag_size = cipher_overhead(suite);
  if (ct.size() < pt.size() + tag_size) {
    throw buffer_too_small_error("Ciphertext buffer too small");
  }

  // Pad nonce to 16 bytes for AES-CTR
  auto padded_nonce = owned_bytes<16>(0);
  padded_nonce.append(nonce);
  padded_nonce.resize(16);

  // Reset AES-CTR context with new nonce (key is preserved)
  if (1 !=
      EVP_EncryptInit_ex(ctx, nullptr, nullptr, nullptr, padded_nonce.data())) {
    throw crypto_error();
  }

  // Encrypt with AES-CTR
  auto inner_ct = ct.subspan(0, pt.size());
  int outlen = 0;
  auto pt_size_int = static_cast<int>(pt.size());
  if (1 != EVP_EncryptUpdate(
             ctx, inner_ct.data(), &outlen, pt.data(), pt_size_int)) {
    throw crypto_error();
  }

  if (1 != EVP_EncryptFinal(ctx, nullptr, &outlen)) {
    throw crypto_error();
  }

  // Compute HMAC tag
  // Reset HMAC context (key is preserved from init)
  if (1 != EVP_MAC_init(hmac, nullptr, 0, nullptr)) {
    throw crypto_error();
  }

  // Build length block
  auto len_block = owned_bytes<24>();
  auto len_view = output_bytes(len_block);
  encode_uint(aad.size(), len_view.first(8));
  encode_uint(inner_ct.size(), len_view.first(16).last(8));
  encode_uint(tag_size, len_view.last(8));

  if (1 != EVP_MAC_update(hmac, len_block.data(), len_block.size())) {
    throw crypto_error();
  }
  if (1 != EVP_MAC_update(hmac, nonce.data(), nonce.size())) {
    throw crypto_error();
  }
  if (1 != EVP_MAC_update(hmac, aad.data(), aad.size())) {
    throw crypto_error();
  }
  if (1 != EVP_MAC_update(hmac, inner_ct.data(), inner_ct.size())) {
    throw crypto_error();
  }

  size_t mac_size = 0;
  auto mac_buf = owned_bytes<64>();
  if (1 != EVP_MAC_final(hmac, mac_buf.data(), &mac_size, mac_buf.size())) {
    throw crypto_error();
  }

  auto tag = ct.subspan(pt.size(), tag_size);
  std::copy(mac_buf.begin(), mac_buf.begin() + tag_size, tag.begin());

  return ct.subspan(0, pt.size() + tag_size);
}

static output_bytes
open_ctr(EVP_CIPHER_CTX* ctx,
         EVP_MAC_CTX* hmac,
         CipherSuite suite,
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

  auto inner_ct = ct.subspan(0, inner_ct_size);
  auto tag = ct.subspan(inner_ct_size, tag_size);

  // Verify HMAC tag
  // Reset HMAC context (key is preserved from init)
  if (1 != EVP_MAC_init(hmac, nullptr, 0, nullptr)) {
    throw crypto_error();
  }

  // Build length block
  auto len_block = owned_bytes<24>();
  auto len_view = output_bytes(len_block);
  encode_uint(aad.size(), len_view.first(8));
  encode_uint(inner_ct.size(), len_view.first(16).last(8));
  encode_uint(tag_size, len_view.last(8));

  if (1 != EVP_MAC_update(hmac, len_block.data(), len_block.size())) {
    throw crypto_error();
  }
  if (1 != EVP_MAC_update(hmac, nonce.data(), nonce.size())) {
    throw crypto_error();
  }
  if (1 != EVP_MAC_update(hmac, aad.data(), aad.size())) {
    throw crypto_error();
  }
  if (1 != EVP_MAC_update(hmac, inner_ct.data(), inner_ct.size())) {
    throw crypto_error();
  }

  size_t mac_size = 0;
  auto mac_buf = owned_bytes<64>();
  if (1 != EVP_MAC_final(hmac, mac_buf.data(), &mac_size, mac_buf.size())) {
    throw crypto_error();
  }

  if (CRYPTO_memcmp(mac_buf.data(), tag.data(), tag_size) != 0) {
    throw authentication_error();
  }

  // Decrypt with AES-CTR
  // Pad nonce to 16 bytes for AES-CTR
  auto padded_nonce = owned_bytes<16>(0);
  padded_nonce.append(nonce);
  padded_nonce.resize(16);

  // Reset AES-CTR context with new nonce (key is preserved)
  if (1 !=
      EVP_EncryptInit_ex(ctx, nullptr, nullptr, nullptr, padded_nonce.data())) {
    throw crypto_error();
  }

  int outlen = 0;
  auto inner_ct_size_int = static_cast<int>(inner_ct_size);
  if (1 != EVP_EncryptUpdate(
             ctx, pt.data(), &outlen, inner_ct.data(), inner_ct_size_int)) {
    throw crypto_error();
  }

  if (1 != EVP_EncryptFinal(ctx, nullptr, &outlen)) {
    throw crypto_error();
  }

  return pt.subspan(0, inner_ct_size);
}

///
/// AEAD Algorithms - GCM
///

static output_bytes
seal_aead(EVP_CIPHER_CTX* ctx,
          CipherSuite suite,
          input_bytes nonce,
          output_bytes ct,
          input_bytes aad,
          input_bytes pt)
{
  auto tag_size = cipher_overhead(suite);
  if (ct.size() < pt.size() + tag_size) {
    throw buffer_too_small_error("Ciphertext buffer too small");
  }

  // Reset context and set new nonce (key is preserved)
  if (1 != EVP_EncryptInit_ex(ctx, nullptr, nullptr, nullptr, nonce.data())) {
    throw crypto_error();
  }

  int outlen = 0;
  auto aad_size_int = static_cast<int>(aad.size());
  if (aad.size() > 0) {
    if (1 !=
        EVP_EncryptUpdate(ctx, nullptr, &outlen, aad.data(), aad_size_int)) {
      throw crypto_error();
    }
  }

  auto pt_size_int = static_cast<int>(pt.size());
  if (1 != EVP_EncryptUpdate(ctx, ct.data(), &outlen, pt.data(), pt_size_int)) {
    throw crypto_error();
  }

  if (1 != EVP_EncryptFinal(ctx, nullptr, &outlen)) {
    throw crypto_error();
  }

  auto tag = ct.subspan(pt.size(), tag_size);
  auto tag_ptr = const_cast<void*>(static_cast<const void*>(tag.data()));
  auto tag_size_downcast = static_cast<int>(tag.size());
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx, EVP_CTRL_GCM_GET_TAG, tag_size_downcast, tag_ptr)) {
    throw crypto_error();
  }

  return ct.subspan(0, pt.size() + tag_size);
}

static output_bytes
open_aead(EVP_CIPHER_CTX* ctx,
          CipherSuite suite,
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

  // Reset context and set new nonce (key is preserved)
  if (1 != EVP_DecryptInit_ex(ctx, nullptr, nullptr, nullptr, nonce.data())) {
    throw crypto_error();
  }

  auto tag = ct.subspan(inner_ct_size, tag_size);
  auto tag_ptr = const_cast<void*>(static_cast<const void*>(tag.data()));
  auto tag_size_downcast = static_cast<int>(tag.size());
  if (1 != EVP_CIPHER_CTX_ctrl(
             ctx, EVP_CTRL_GCM_SET_TAG, tag_size_downcast, tag_ptr)) {
    throw crypto_error();
  }

  int out_size;
  auto aad_size_int = static_cast<int>(aad.size());
  if (aad.size() > 0) {
    if (1 !=
        EVP_DecryptUpdate(ctx, nullptr, &out_size, aad.data(), aad_size_int)) {
      throw crypto_error();
    }
  }

  auto inner_ct_size_int = static_cast<int>(inner_ct_size);
  if (1 != EVP_DecryptUpdate(
             ctx, pt.data(), &out_size, ct.data(), inner_ct_size_int)) {
    throw crypto_error();
  }

  if (1 != EVP_DecryptFinal(ctx, nullptr, &out_size)) {
    throw authentication_error();
  }

  return pt.subspan(0, inner_ct_size);
}

///
/// CipherState seal/open methods
///

output_bytes
CipherState::seal(input_bytes nonce,
                  output_bytes ct,
                  input_bytes aad,
                  input_bytes pt)
{
  if (is_ctr_hmac_suite(suite)) {
    return seal_ctr(cipher_handle->ctx.get(),
                    hmac_handle->ctx.get(),
                    suite,
                    nonce,
                    ct,
                    aad,
                    pt);
  }
  return seal_aead(cipher_handle->ctx.get(), suite, nonce, ct, aad, pt);
}

output_bytes
CipherState::open(input_bytes nonce,
                  output_bytes pt,
                  input_bytes aad,
                  input_bytes ct)
{
  if (is_ctr_hmac_suite(suite)) {
    return open_ctr(cipher_handle->ctx.get(),
                    hmac_handle->ctx.get(),
                    suite,
                    nonce,
                    pt,
                    aad,
                    ct);
  }
  return open_aead(cipher_handle->ctx.get(), suite, nonce, pt, aad, ct);
}

///
/// Stateless seal/open (used by test vectors)
///

output_bytes
seal(CipherSuite suite,
     input_bytes key,
     input_bytes nonce,
     output_bytes ct,
     input_bytes aad,
     input_bytes pt)
{
  auto state = CipherState::create_seal(suite, key);
  return state.seal(nonce, ct, aad, pt);
}

output_bytes
open(CipherSuite suite,
     input_bytes key,
     input_bytes nonce,
     output_bytes pt,
     input_bytes aad,
     input_bytes ct)
{
  auto state = CipherState::create_open(suite, key);
  return state.open(nonce, pt, aad, ct);
}

///
/// HKDF
///

using scoped_evp_kdf = std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)>;
using scoped_evp_kdf_ctx =
  std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)>;

owned_bytes<max_hkdf_expand_size>
hkdf_extract(CipherSuite suite, input_bytes salt, input_bytes ikm)
{
  auto mode = EVP_KDF_HKDF_MODE_EXTRACT_ONLY;
  auto digest_name = openssl_digest_name(suite);
  auto* salt_ptr =
    const_cast<void*>(reinterpret_cast<const void*>(salt.data()));
  auto* ikm_ptr = const_cast<void*>(reinterpret_cast<const void*>(ikm.data()));

  const auto params = std::array<OSSL_PARAM, 5>{
    OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
    OSSL_PARAM_construct_utf8_string(
      OSSL_KDF_PARAM_DIGEST, digest_name.data(), digest_name.size()),
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
    throw crypto_error();
  }

  const auto digest_size = EVP_KDF_CTX_get_kdf_size(ctx.get());
  auto out = owned_bytes<max_hkdf_expand_size>(digest_size);
  if (1 != EVP_KDF_derive(ctx.get(), out.data(), out.size(), nullptr)) {
    throw crypto_error();
  }

  return out;
}

owned_bytes<max_hkdf_extract_size>
hkdf_expand(CipherSuite suite, input_bytes prk, input_bytes info, size_t size)
{
  auto mode = EVP_KDF_HKDF_MODE_EXPAND_ONLY;
  auto digest_name = openssl_digest_name(suite);
  auto* prk_ptr = const_cast<void*>(reinterpret_cast<const void*>(prk.data()));
  auto* info_ptr =
    const_cast<void*>(reinterpret_cast<const void*>(info.data()));

  const auto params = std::array<OSSL_PARAM, 5>{
    OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode),
    OSSL_PARAM_construct_utf8_string(
      OSSL_KDF_PARAM_DIGEST, digest_name.data(), digest_name.size()),
    OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, prk_ptr, prk.size()),
    OSSL_PARAM_construct_octet_string(
      OSSL_KDF_PARAM_INFO, info_ptr, info.size()),
    OSSL_PARAM_construct_end(),
  };

  const auto kdf =
    scoped_evp_kdf(EVP_KDF_fetch(NULL, "HKDF", NULL), EVP_KDF_free);
  const auto ctx =
    scoped_evp_kdf_ctx(EVP_KDF_CTX_new(kdf.get()), EVP_KDF_CTX_free);

  auto out = owned_bytes<max_hkdf_expand_size>(size);
  if (1 != EVP_KDF_derive(ctx.get(), out.data(), out.size(), params.data())) {
    throw crypto_error();
  }

  return out;
}

} // namespace SFRAME_NAMESPACE

#endif // defined(OPENSSL_3)
