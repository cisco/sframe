#pragma once

#include <openssl/hmac.h>
#include <sframe/sframe.h>

#include <array>
#include <cassert>

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

template<size_t N>
struct owned_bytes {
  owned_bytes()
    : _size(N)
  {
    std::fill(_data.begin(), _data.end(), 0);
  }

  uint8_t* data() { return _data.data(); }
  auto begin() { return _data.begin(); }

  size_t size() const { return _size; }
  void resize(size_t size) {
    assert(size < N);
    _size = size;
  }

  // TODO(RLB) Delete this once allocations are not needed downstream
  explicit operator bytes() const { return bytes(_data.begin(), _data.end()); }

  operator input_bytes() const { return input_bytes(_data).first(_size); }
  operator output_bytes() { return output_bytes(_data).first(_size); }

  private:
  std::array<uint8_t, N> _data;
  size_t _size;
};


struct HMAC
{
  using Output = owned_bytes<EVP_MAX_MD_SIZE>;

  HMAC(CipherSuite suite, input_bytes key);
  void write(input_bytes data);
  Output digest();

  private:
  scoped_hmac_ctx ctx;
};

HMAC::Output
hkdf_extract(CipherSuite suite, input_bytes salt, input_bytes ikm);

HMAC::Output
hkdf_expand(CipherSuite suite,
            input_bytes prk,
            input_bytes info,
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
