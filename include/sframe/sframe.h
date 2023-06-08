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

struct Header;

class SFrame
{
protected:
  SFrame(CipherSuite suite_in);
  virtual ~SFrame();

  struct KeyAndSalt
  {
    static KeyAndSalt from_base_key(CipherSuite suite, const bytes& base_key);

    bytes key;
    bytes salt;
    Counter counter;
  };

  void add_key(KeyID kid, const bytes& key);

  output_bytes _protect(const Header& header,
                        output_bytes ciphertext,
                        input_bytes plaintext);
  output_bytes _unprotect(const Header& header,
                          output_bytes ciphertext,
                          input_bytes plaintext);

  CipherSuite suite;
  std::map<KeyID, KeyAndSalt> keys;
};

class Context : protected SFrame
{
public:
  Context(CipherSuite suite);

  void add_key(KeyID kid, const bytes& key);

  output_bytes protect(KeyID key_id,
                       output_bytes ciphertext,
                       input_bytes plaintext);
  output_bytes unprotect(output_bytes plaintext, input_bytes ciphertext);

protected:
  std::map<KeyID, Counter> counters;
};

class MLSContext : protected Context
{
public:
  using EpochID = uint64_t;
  using SenderID = uint64_t;
  using ContextID = uint64_t;

  MLSContext(CipherSuite suite_in, size_t epoch_bits_in);

  void add_epoch(EpochID epoch_id, const bytes& sframe_epoch_secret);
  void add_epoch(EpochID epoch_id,
                 const bytes& sframe_epoch_secret,
                 size_t sender_bits);
  void purge_before(EpochID keeper);

  output_bytes protect(EpochID epoch_id,
                       SenderID sender_id,
                       output_bytes ciphertext,
                       input_bytes plaintext);
  output_bytes protect(EpochID epoch_id,
                       SenderID sender_id,
                       ContextID context_id,
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
    size_t sender_bits;
    size_t context_bits;
    uint64_t max_sender_id;
    uint64_t max_context_id;
    std::map<SenderID, KeyAndSalt> sender_keys;

    EpochKeys(EpochID full_epoch_in,
              bytes sframe_epoch_secret_in,
              size_t epoch_bits,
              size_t sender_bits_in);
    bytes base_key(CipherSuite suite, SenderID sender_id) const;
    KeyAndSalt& get(CipherSuite suite, SenderID sender_id);
  };

  void purge_epoch(EpochID epoch_id);

  KeyID form_key_id(EpochID epoch_id,
                    SenderID sender_id,
                    ContextID context_id) const;
  void ensure_key(KeyID key_id);

  std::vector<std::unique_ptr<EpochKeys>> epoch_cache;
  KeyAndSalt& get_state(KeyID key_id);
};

} // namespace sframe
