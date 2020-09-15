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

using KeyID = uint64_t;
using Counter = uint64_t;

struct KeyState
{
  static KeyState from_base_key(CipherSuite suite, const bytes& base_key);

  bytes key;
  bytes salt;
  Counter counter;
};

class Context
{
public:
  Context(CipherSuite suite);

  void add_key(KeyID kid, const bytes& key);

  output_bytes protect(KeyID key_id,
                       output_bytes ciphertext,
                       input_bytes plaintext);
  output_bytes unprotect(output_bytes plaintext, input_bytes ciphertext);

private:
  const CipherSuite suite;
  std::map<KeyID, KeyState> state;
};

class MLSContext
{
public:
  using EpochID = uint64_t;
  using SenderID = uint32_t;

  MLSContext(CipherSuite suite_in, size_t epoch_bits_in);

  void add_epoch(EpochID epoch_id, const bytes& sframe_epoch_secret);

  output_bytes protect(EpochID epoch_id,
                       SenderID sender_id,
                       output_bytes ciphertext,
                       input_bytes plaintext);
  output_bytes unprotect(output_bytes plaintext, input_bytes ciphertext);

private:
  const CipherSuite suite;
  const size_t epoch_bits;
  const size_t epoch_mask;

  struct EpochKeys
  {
    const bytes sframe_epoch_secret;
    std::map<SenderID, KeyState> sender_keys;

    EpochKeys(bytes sframe_epoch_secret);
    KeyState& get(CipherSuite suite, SenderID sender_id);
  };

  std::vector<std::optional<EpochKeys>> epoch_cache;
};

} // namespace sframe
