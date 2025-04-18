#pragma once

#include <openssl/hmac.h>
#include <sframe/sframe.h>

#include <array>

namespace sframe {

///
/// Scoped pointers for OpenSSL objects
///

using scoped_evp_ctx =
  std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;
using scoped_hmac_ctx = std::unique_ptr<HMAC_CTX, decltype(&HMAC_CTX_free)>;

///
/// Information about algorithms
///

size_t
cipher_digest_size(CipherSuite suite);
size_t
cipher_key_size(CipherSuite suite);
size_t
cipher_nonce_size(CipherSuite suite);

///
/// HMAC and HKDF
///

struct HMAC
{
  HMAC(CipherSuite suite, input_bytes key);
  void write(input_bytes data);
  input_bytes digest();

  scoped_hmac_ctx ctx;
  std::array<uint8_t, EVP_MAX_MD_SIZE> md;
};

bytes
hkdf_extract(CipherSuite suite, const bytes& salt, const bytes& ikm);

bytes
hkdf_expand(CipherSuite suite,
            const bytes& secret,
            const bytes& info,
            size_t size);

///
/// AEAD Algorithms
///

size_t
overhead(CipherSuite suite);

output_bytes
seal(CipherSuite suite,
     input_bytes key,
     input_bytes nonce,
     output_bytes ct,
     input_bytes aad,
     input_bytes pt);

output_bytes
open(CipherSuite suite,
     input_bytes key,
     input_bytes nonce,
     output_bytes pt,
     input_bytes aad,
     input_bytes ct);

} // namespace sframe
