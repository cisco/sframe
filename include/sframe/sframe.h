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

class Header
{
public:
  const KeyID key_id;
  const Counter counter;

  Header(KeyID key_id_in, Counter counter_in);
  static Header parse(input_bytes buffer);

  input_bytes encoded() const;
  size_t size() const;

private:
  static constexpr size_t min_size = 1;
  static constexpr size_t max_size = 1 + 7 + 7;

  const size_t key_id_size;
  const size_t counter_size;
  std::array<uint8_t, max_size> buffer;

  Header(KeyID key_id_in, Counter counter_in, input_bytes encoded);
};

// ContextBase represents the core SFrame encryption logic.  It remembers a set
// of keys and salts identified by key IDs, and uses them to protect and
// unprotect payloads.  The SFrame header is **not** written by the protect
// method or read by the unprotect method.  It is assumed that the application
// carries the header values in some other way.
//
// In general, you should prefer Context to ContextBase.
class ContextBase
{
public:
  ContextBase(CipherSuite suite_in);
  virtual ~ContextBase();

  void add_key(KeyID kid, const bytes& key);

  output_bytes protect(const Header& header,
                       output_bytes ciphertext,
                       input_bytes plaintext);
  output_bytes unprotect(const Header& header,
                         output_bytes ciphertext,
                         input_bytes plaintext);

protected:
  struct KeyAndSalt
  {
    static KeyAndSalt from_base_key(CipherSuite suite, const bytes& base_key);

    bytes key;
    bytes salt;
    Counter counter;
  };

  CipherSuite suite;
  std::map<KeyID, KeyAndSalt> keys;
};

// Context applies the full SFrame transform.  It tracks a counter for each key
// to ensure nonce uniqueness, adds the SFrame header on protect, and
// reads/strips the SFrame header on unprotect.
class Context : protected ContextBase
{
public:
  Context(CipherSuite suite);
  virtual ~Context();

  void add_key(KeyID kid, const bytes& key);

  output_bytes protect(KeyID key_id,
                       output_bytes ciphertext,
                       input_bytes plaintext);
  output_bytes unprotect(output_bytes plaintext, input_bytes ciphertext);

protected:
  std::map<KeyID, Counter> counters;
};

// MLSContext augments Context with logic for deriving keys from MLS.  Instead
// of adding individual keys, salts, and key IDs, the caller adds a secret for an epoch,
// and keys / salts / key IDs are derived as needed.
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
  struct EpochKeys
  {
    const EpochID full_epoch;
    const bytes sframe_epoch_secret;
    size_t sender_bits;
    size_t context_bits;
    uint64_t max_sender_id;
    uint64_t max_context_id;

    EpochKeys(EpochID full_epoch_in,
              bytes sframe_epoch_secret_in,
              size_t epoch_bits,
              size_t sender_bits_in);
    bytes base_key(CipherSuite suite, SenderID sender_id) const;
  };

  void purge_epoch(EpochID epoch_id);

  KeyID form_key_id(EpochID epoch_id,
                    SenderID sender_id,
                    ContextID context_id) const;
  void ensure_key(KeyID key_id);

  const size_t epoch_bits;
  const size_t epoch_mask;
  std::vector<std::unique_ptr<EpochKeys>> epoch_cache;
};

} // namespace sframe
