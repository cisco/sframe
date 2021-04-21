#pragma once

#include <iosfwd>
#include <map>
#include <memory>
#include <vector>

#include <gsl/gsl-lite.hpp>

namespace sframe {

struct openssl_error : std::runtime_error
{
  openssl_error();
};

struct unsupported_ciphersuite_error : std::runtime_error
{
  unsupported_ciphersuite_error();
};

struct authentication_error : std::runtime_error
{
  authentication_error();
};

struct buffer_too_small_error : std::runtime_error
{
  using parent = std::runtime_error;
  using parent::parent;
};

struct invalid_parameter_error : std::runtime_error
{
  using parent = std::runtime_error;
  using parent::parent;
};

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

class SFrame
{
protected:
  CipherSuite suite;

  SFrame(CipherSuite suite_in);
  virtual ~SFrame();

  struct KeyState
  {
    static KeyState from_base_key(CipherSuite suite, const bytes& base_key);

    bytes key;
    bytes salt;
    Counter counter;
  };

  output_bytes _protect(KeyID key_id,
                        output_bytes ciphertext,
                        input_bytes plaintext);
  output_bytes _unprotect(output_bytes ciphertext, input_bytes plaintext);

  virtual KeyState& get_state(KeyID key_id) = 0;
};

class Context : public SFrame
{
public:
  Context(CipherSuite suite);

  void add_key(KeyID kid, const bytes& key);

  output_bytes protect(KeyID key_id,
                       output_bytes ciphertext,
                       input_bytes plaintext);
  output_bytes unprotect(output_bytes plaintext, input_bytes ciphertext);

private:
  std::map<KeyID, KeyState> state;

  KeyState& get_state(KeyID key_id) override;
};

class MLSContext : public SFrame
{
public:
  using EpochID = uint64_t;
  using SenderID = uint32_t;

  MLSContext(CipherSuite suite_in, size_t epoch_bits_in);

  void add_epoch(EpochID epoch_id, const bytes& sframe_epoch_secret);
  void purge_before(EpochID keeper);

  output_bytes protect(EpochID epoch_id,
                       SenderID sender_id,
                       output_bytes ciphertext,
                       input_bytes plaintext);
  output_bytes unprotect(output_bytes plaintext, input_bytes ciphertext);

private:
  const size_t epoch_bits;
  const size_t epoch_mask;

  struct EpochKeys
  {
    const EpochID full_epoch;
    const bytes sframe_epoch_secret;
    std::map<SenderID, KeyState> sender_keys;

    EpochKeys(EpochID full_epoch_in, bytes sframe_epoch_secret_in);
    KeyState& get(CipherSuite suite, SenderID sender_id);
  };

  std::vector<std::unique_ptr<EpochKeys>> epoch_cache;
  KeyState& get_state(KeyID key_id) override;
};

} // namespace sframe
