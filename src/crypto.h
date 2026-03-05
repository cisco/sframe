#pragma once

#include <sframe/sframe.h>

#include <memory>

namespace SFRAME_NAMESPACE {

///
/// CipherState - pre-warmed cipher state for efficient repeated operations
///
/// Holds a pre-initialized cipher context so that expensive key schedule
/// computation happens once at construction, not on every seal/open call.
///

struct CipherHandle;

struct CipherState
{
  static CipherState create_seal(CipherSuite suite, input_bytes key);
  static CipherState create_open(CipherSuite suite, input_bytes key);

  output_bytes seal(input_bytes nonce,
                    output_bytes ct,
                    input_bytes aad,
                    input_bytes pt);

  output_bytes open(input_bytes nonce,
                    output_bytes pt,
                    input_bytes aad,
                    input_bytes ct);

private:
  struct Deleter
  {
    void operator()(CipherHandle* h) const;
  };

  std::unique_ptr<CipherHandle, Deleter> handle;

  explicit CipherState(CipherHandle* h);
};

size_t
cipher_digest_size(CipherSuite suite);
size_t
cipher_key_size(CipherSuite suite);
size_t
cipher_enc_key_size(CipherSuite suite);
size_t
cipher_nonce_size(CipherSuite suite);
size_t
cipher_overhead(CipherSuite suite);

///
/// HKDF
///

static constexpr size_t max_hkdf_extract_size = 64;
static constexpr size_t max_hkdf_expand_size = 64;

owned_bytes<max_hkdf_extract_size>
hkdf_extract(CipherSuite suite, input_bytes salt, input_bytes ikm);

owned_bytes<max_hkdf_expand_size>
hkdf_expand(CipherSuite suite, input_bytes prk, input_bytes info, size_t size);

///
/// AEAD Algorithms
///

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

} // namespace SFRAME_NAMESPACE
