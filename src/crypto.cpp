#include "crypto.h"
#include "header.h"

namespace sframe {

size_t
cipher_digest_size(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32:
    case CipherSuite::AES_GCM_128_SHA256:
      return 32;

    case CipherSuite::AES_GCM_256_SHA512:
      return 64;

    default:
      throw unsupported_ciphersuite_error();
  }
}

size_t
cipher_key_size(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32:
      // 16-byte AES key + 32-byte HMAC key
      return 48;

    case CipherSuite::AES_GCM_128_SHA256:
      return 16;

    case CipherSuite::AES_GCM_256_SHA512:
      return 32;

    default:
      throw unsupported_ciphersuite_error();
  }
}

size_t
cipher_enc_key_size(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32:
      return 16;

    default:
      throw unsupported_ciphersuite_error();
  }
}

size_t
cipher_nonce_size(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
    case CipherSuite::AES_128_CTR_HMAC_SHA256_32:
    case CipherSuite::AES_GCM_128_SHA256:
    case CipherSuite::AES_GCM_256_SHA512:
      return 12;

    default:
      throw unsupported_ciphersuite_error();
  }
}

size_t
cipher_overhead(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_128_CTR_HMAC_SHA256_80:
      return 10; // 80-bit tag

    case CipherSuite::AES_128_CTR_HMAC_SHA256_64:
      return 8; // 64-bit tag

    case CipherSuite::AES_128_CTR_HMAC_SHA256_32:
      return 4; // 32-bit tag

    case CipherSuite::AES_GCM_128_SHA256:
    case CipherSuite::AES_GCM_256_SHA512:
      return 16; // Full 128-bit AES-GCM tag

    default:
      throw unsupported_ciphersuite_error();
  }
}

} // namespace sframe
