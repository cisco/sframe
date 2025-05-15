#pragma once

#include <sframe/sframe.h>

#include <array>

namespace sframe {

///
/// Information about algorithms
///

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
/// HMAC and HKDF
///

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

output_bytes
seal(CipherSuite suite,
     const bytes& key,
     const bytes& nonce,
     output_bytes ct,
     input_bytes aad,
     input_bytes pt);

output_bytes
open(CipherSuite suite,
     const bytes& key,
     const bytes& nonce,
     output_bytes pt,
     input_bytes aad,
     input_bytes ct);

} // namespace sframe
