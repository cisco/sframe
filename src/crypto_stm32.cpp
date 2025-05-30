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
    auto retval = func;                                                        \
    if (retval != success_code) {                                              \
      cmox_error = retval;                                                     \
      throw crypto_error();                                                    \
    }                                                                          \
  } while (0)

///
/// Convert between native identifiers / errors and cmox ones
///

std::optional<int> cmox_error;

crypto_error::crypto_error()
  : std::runtime_error(
      cmox_error.has_value()
        ? "CMOX crypto error (error=" + std::to_string(cmox_error.value()) + ")"
        : "unknown CMOX crypto error")
{
}

extern "C"
{
  static cmox_mac_algo_t cmox_hmac_algo(CipherSuite suite)
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

  static cmox_hmac_impl_t cmox_hmac_impl(CipherSuite suite)
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

  static std::size_t cmox_hmac_size(CipherSuite suite)
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
  auto N = static_cast<uint32_t>(size / digest_size);
  if ((N * digest_size) < size) {
    N++;
  }

  mac_ctx = cmox_hmac_construct(&Hmac_Ctx, cmox_hmac_impl(suite));
  if (mac_ctx == nullptr) {
    throw crypto_error();
  }

  owned_bytes<max_hkdf_expand_size> computed_hash(size);
  owned_bytes<max_hkdf_expand_size> out(size);

  uint32_t index = 0;
  for (uint8_t i = 1; i <= N; i++) {
    VERIFY_CMOX_CALL(cmox_mac_init(mac_ctx), CMOX_MAC_SUCCESS);

    if (i == N) {
      VERIFY_CMOX_CALL(cmox_mac_setTagLen(mac_ctx, size - index),
                       CMOX_MAC_SUCCESS);
    }

    VERIFY_CMOX_CALL(cmox_mac_setKey(mac_ctx, prk.data(), prk.size()),
                     CMOX_MAC_SUCCESS);

    if (i > 1) {
      VERIFY_CMOX_CALL(
        cmox_mac_append(mac_ctx, computed_hash.data(), digest_size),
        CMOX_MAC_SUCCESS);
    }

    VERIFY_CMOX_CALL(cmox_mac_append(mac_ctx, info.data(), info.size()),
                     CMOX_MAC_SUCCESS);
    VERIFY_CMOX_CALL(cmox_mac_append(mac_ctx, &i, 1), CMOX_MAC_SUCCESS);
    VERIFY_CMOX_CALL(
      cmox_mac_generateTag(mac_ctx, computed_hash.data(), nullptr),
      CMOX_MAC_SUCCESS);

    if (i == N) {
      memcpy(&out[index], computed_hash.data(), size - index);
      index = size;
    } else {
      memcpy(&out[index], computed_hash.data(), digest_size);
      index += digest_size;
    }
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
      throw unsupported_ciphersuite_error();
    }

    case CipherSuite::AES_GCM_128_SHA256:
    case CipherSuite::AES_GCM_256_SHA512: {
      return seal_aead(suite, key, nonce, ct, aad, pt);
    }

    default:
      throw unsupported_ciphersuite_error();
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
      throw unsupported_ciphersuite_error();
      // return open_ctr(suite, key, nonce, pt, aad, ct);
    }

    case CipherSuite::AES_GCM_128_SHA256:
    case CipherSuite::AES_GCM_256_SHA512: {
      return open_aead(suite, key, nonce, pt, aad, ct);
    }
    default:
      throw unsupported_ciphersuite_error();
  }

  throw unsupported_ciphersuite_error();
}

} // namespace sframe

#endif
