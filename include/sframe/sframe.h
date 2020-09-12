#pragma once

#include <iosfwd>
#include <map>
#include <vector>

#include <gsl/gsl>

namespace sframe {

enum class CipherSuite : uint16_t
{
  AES_CM_128_HMAC_SHA256_4 = 1,
  AES_CM_128_HMAC_SHA256_8 = 2,
  AES_GCM_128_SHA256 = 3,
  AES_GCM_256_SHA512 = 4,
};

constexpr size_t max_overhead = 17 + 16;

using bytes = std::vector<uint8_t>;
using input_bytes = gsl::span<const uint8_t>;
using output_bytes = gsl::span<uint8_t>;

std::ostream&
operator<<(std::ostream& str, const input_bytes data);

using KeyID = uint64_t;
using Counter = uint64_t;

class Context
{
public:
  Context(CipherSuite suite);

  void add_key(KeyID kid, const bytes& key);

  output_bytes protect(KeyID key_id, output_bytes ciphertext, input_bytes plaintext);
  output_bytes unprotect(output_bytes plaintext, input_bytes ciphertext);

private:
  struct KeyState
  {
    bytes key;
    bytes salt;
    Counter counter;
  };

  const CipherSuite suite;
  std::map<KeyID, KeyState> state;
};

} // namespace sframe
