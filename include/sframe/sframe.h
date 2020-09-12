#pragma once

#include <iosfwd>
#include <map>
#include <vector>

namespace sframe {

enum class CipherSuite : uint16_t
{
  AES_CM_128_HMAC_SHA256_4 = 1,
  AES_CM_128_HMAC_SHA256_8 = 2,
  AES_GCM_128_SHA256 = 3,
  AES_GCM_256_SHA512 = 4,
};

const size_t max_overhead = 12 + 16;

using bytes = std::vector<uint8_t>;
std::ostream&
operator<<(std::ostream& str, const bytes& data);

using KeyID = uint64_t;
using Counter = uint64_t;

class Context
{
public:
  Context(CipherSuite suite);

  void add_key(KeyID kid, const bytes& key);

  bytes protect(KeyID key_id, const bytes& plaintext);
  bytes unprotect(const bytes& ciphertext);

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
