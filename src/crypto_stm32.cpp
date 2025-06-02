#if defined(STM32)

#include "crypto.h"
#include "header.h"

#include <cmox_crypto.h>
#include <cmox_init.h>
#include <cmox_low_level.h>
#include <mac/cmox_hmac.h>

#include <cstring>

namespace sframe {

#define VERIFY_CMOX_CALL(func, success_code)                                   \
  do {                                                                         \
    const auto retval = func;                                                  \
    if (retval != success_code) {                                              \
      throw crypto_error(retval);                                              \
    }                                                                          \
  } while (0)

///
/// Convert between native identifiers / errors and cmox ones
///

crypto_error::crypto_error()
  : std::runtime_error("unknown CMOX crypto error")
{
}

crypto_error::crypto_error(std::size_t err_code)
  : std::runtime_error(
      "CMOX crypto error (error_code=" + std::to_string(err_code) + ")")
{
}

crypto_error::crypto_error(const std::string& err_str)
  : std::runtime_error("CMOX crypto error (error=" + err_str + ")")
{
}

static cmox_mac_algo_t
cmox_hmac_algo(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32:
    case CipherSuite::AES_GCM_128_SHA256:
      return CMOX_HMAC_SHA256_ALGO;
    case CipherSuite::AES_GCM_256_SHA512:
      return CMOX_HMAC_SHA512_ALGO;
    default:
      throw unsupported_ciphersuite_error();
  }
}

static cmox_hmac_impl_t
cmox_hmac_impl(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32:
    case CipherSuite::AES_GCM_128_SHA256:
      return CMOX_HMAC_SHA256;
    case CipherSuite::AES_GCM_256_SHA512:
      return CMOX_HMAC_SHA512;
    default:
      throw unsupported_ciphersuite_error();
  }
}

static std::size_t
cmox_hmac_size(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32:
    case CipherSuite::AES_GCM_128_SHA256:
      return CMOX_SHA256_SIZE;
    case CipherSuite::AES_GCM_256_SHA512:
      return CMOX_SHA512_SIZE;
    default:
      throw unsupported_ciphersuite_error();
  }
}

///
/// HKDF
///

owned_bytes<max_hkdf_extract_size>
hkdf_extract(CipherSuite suite, input_bytes salt, input_bytes ikm)
{
  std::size_t computed_size = 0;
  const auto hmac_size = cmox_hmac_size(suite);
  auto out = owned_bytes<max_hkdf_extract_size>(hmac_size);
  VERIFY_CMOX_CALL(cmox_mac_compute(cmox_hmac_algo(suite),
                                    ikm.data(),
                                    ikm.size(),
                                    salt.data(),
                                    salt.size(),
                                    nullptr,
                                    0,
                                    out.data(),
                                    out.size(),
                                    &computed_size),
                   CMOX_MAC_SUCCESS);

  return out;
}

owned_bytes<max_hkdf_extract_size>
hkdf_expand(CipherSuite suite, input_bytes prk, input_bytes info, size_t size)
{
  cmox_hmac_handle_t Hmac_Ctx;
  cmox_mac_handle_t* mac_ctx;

  const auto digest_size = cmox_hmac_size(suite);
  auto N = static_cast<uint32_t>((size + digest_size - 1) / digest_size);

  mac_ctx = cmox_hmac_construct(&Hmac_Ctx, cmox_hmac_impl(suite));
  if (mac_ctx == nullptr) {
    throw crypto_error();
  }

  owned_bytes<max_hkdf_extract_size> computed_hash(digest_size);
  owned_bytes<max_hkdf_expand_size> out(size);

  uint32_t index = 0;
  for (uint8_t i = 1; i <= N; i++) {
    computed_hash.resize(0);

    VERIFY_CMOX_CALL(cmox_mac_init(mac_ctx), CMOX_MAC_SUCCESS);

    VERIFY_CMOX_CALL(cmox_mac_setKey(mac_ctx, prk.data(), prk.size()),
                     CMOX_MAC_SUCCESS);

    VERIFY_CMOX_CALL(cmox_mac_append(mac_ctx, info.data(), info.size()),
                     CMOX_MAC_SUCCESS);

    VERIFY_CMOX_CALL(cmox_mac_append(mac_ctx, &i, 1), CMOX_MAC_SUCCESS);

    computed_hash.resize(digest_size);
    VERIFY_CMOX_CALL(
      cmox_mac_generateTag(mac_ctx, computed_hash.data(), nullptr),
      CMOX_MAC_SUCCESS);

    const auto to_copy = (i == N) ? size - index : digest_size;
    std::memcpy(&out[index], computed_hash.data(), to_copy);
    index += to_copy;
  }

  VERIFY_CMOX_CALL(cmox_mac_cleanup(mac_ctx), CMOX_MAC_SUCCESS);

  return out;
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

  std::size_t computed_size = 0;
  VERIFY_CMOX_CALL(cmox_aead_encrypt(CMOX_AESFAST_GCMFAST_ENC_ALGO,
                                     pt.data(),
                                     pt.size(),
                                     tag_size,
                                     key.data(),
                                     key.size(),
                                     nonce.data(),
                                     nonce.size(),
                                     aad.data(),
                                     aad.size(),
                                     ct.data(),
                                     &computed_size),
                   CMOX_CIPHER_SUCCESS);

  return ct.subspan(0, computed_size);
}

output_bytes
seal(CipherSuite suite,
     input_bytes key,
     input_bytes nonce,
     output_bytes ct,
     input_bytes aad,
     input_bytes pt)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32: {
      // TODO(GhostofCookie): return seal_ctr(suite, key, nonce, ct, aad, pt);
      throw unsupported_ciphersuite_error();
    }

    case CipherSuite::AES_GCM_128_SHA256:
    case CipherSuite::AES_GCM_256_SHA512: {
      return seal_aead(suite, key, nonce, ct, aad, pt);
    }
  }

  throw unsupported_ciphersuite_error();
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

  std::size_t computed_size = 0;
  VERIFY_CMOX_CALL(cmox_aead_decrypt(CMOX_AESFAST_GCMFAST_DEC_ALGO,
                                     ct.data(),
                                     ct.size(),
                                     tag_size,
                                     key.data(),
                                     key.size(),
                                     nonce.data(),
                                     nonce.size(),
                                     aad.data(),
                                     aad.size(),
                                     pt.data(),
                                     &computed_size),
                   CMOX_CIPHER_AUTH_SUCCESS);

  return pt.subspan(0, computed_size);
}

output_bytes
open(CipherSuite suite,
     input_bytes key,
     input_bytes nonce,
     output_bytes pt,
     input_bytes aad,
     input_bytes ct)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32: {
      // TODO(GhostofCookie): return open_ctr(suite, key, nonce, pt, aad, ct);
      throw unsupported_ciphersuite_error();
    }

    case CipherSuite::AES_GCM_128_SHA256:
    case CipherSuite::AES_GCM_256_SHA512: {
      return open_aead(suite, key, nonce, pt, aad, ct);
    }
  }

  throw unsupported_ciphersuite_error();
}

} // namespace sframe

#endif
