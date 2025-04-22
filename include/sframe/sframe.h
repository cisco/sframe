#pragma once

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
  AES_128_CTR_HMAC_SHA256_80 = 1,
  AES_128_CTR_HMAC_SHA256_64 = 2,
  AES_128_CTR_HMAC_SHA256_32 = 3,
  AES_GCM_128_SHA256 = 4,
  AES_GCM_256_SHA512 = 5,
};

constexpr size_t max_overhead = 17 + 16;

using input_bytes = gsl::span<const uint8_t>;
using output_bytes = gsl::span<uint8_t>;

using KeyID = uint64_t;
using Counter = uint64_t;

template<typename T, size_t N>
class vector
{
private:
  std::array<T, N> _data;
  size_t _size;

public:
  constexpr vector()
    : _size(N)
  {
    std::fill(_data.begin(), _data.end(), T());
  }

  constexpr vector(size_t size)
    : _size(size)
  {
    std::fill(_data.begin(), _data.end(), T());
  }

  constexpr vector(std::initializer_list<uint8_t> content)
  {
    resize(content.size());
    std::copy(content.begin(), content.end(), _data.begin());
  }

  constexpr vector(gsl::span<const T> content)
  {
    resize(content.size());
    std::copy(content.begin(), content.end(), _data.begin());
  }

  // XXX(RLB) This constructor seems redundant with the prior one, but for some
  // reason the compiler won't auto-convert from vector to span.
  template<size_t M>
  constexpr vector(const vector<T, M>& content)
  {
    resize(content.size());
    std::copy(content.begin(), content.end(), _data.begin());
  }

  uint8_t* data() { return _data.data(); }

  auto begin() const { return _data.begin(); }
  auto begin() { return _data.begin(); }

  auto end() const { return _data.begin() + _size; }
  auto end() { return _data.end() + _size; }

  auto size() const { return _size; }
  void resize(size_t size)
  {
    if (size > N) {
      throw std::out_of_range("vector out of space");
    }

    _size = size;
  }

  void push(T&& item)
  {
    resize(_size + 1);
    _data.at(_size - 1) = item;
  }

  void append(input_bytes content) {
    const auto start = _size;
    resize(_size + content.size());
    std::copy(content.begin(), content.end(), begin() + start);
  }

  auto& operator[](size_t i) { return _data.at(i); }
  const auto& operator[](size_t i) const { return _data.at(i); }

  operator gsl::span<const T>() const { return gsl::span(_data).first(_size); }
  operator gsl::span<T>() { return gsl::span(_data).first(_size); }
};

template<typename K, typename V, size_t N>
class map : private vector<std::optional<std::pair<K, V>>, N>
{
public:
  template<class... Args>
  void emplace(Args&&... args)
  {
    const auto pos = std::find_if(
      this->begin(), this->end(), [&](const auto& pair) { return !pair; });
    if (pos == this->end()) {
      throw std::out_of_range("map out of space");
    }

    pos->emplace(args...);
  }

  auto find(const K& key) const
  {
    return std::find_if(this->begin(), this->end(), [&](const auto& pair) {
      return pair && pair.value().first == key;
    });
  }

  auto find(const K& key)
  {
    return std::find_if(this->begin(), this->end(), [&](const auto& pair) {
      return pair && pair.value().first == key;
    });
  }

  bool contains(const K& key) const { return find(key) != this->end(); }

  const V& at(const K& key) const
  {
    const auto pos = find(key);
    if (pos == this->end()) {
      throw std::out_of_range("map key not found");
    }

    return pos->value().second;
  }

  V& at(const K& key)
  {
    auto pos = find(key);
    if (pos == this->end()) {
      throw std::out_of_range("map key not found");
    }

    return pos->value().second;
  }

  template<typename F>
  void erase_if_key(F&& f)
  {
    const auto to_erase = [&f](const auto& maybe_pair) {
      return maybe_pair && f(maybe_pair.value().first);
    };

    std::replace_if(this->begin(), this->end(), to_erase, std::nullopt);
  }
};

template<size_t N>
using owned_bytes = vector<uint8_t, N>;

class Header
{
public:
  const KeyID key_id;
  const Counter counter;

  Header(KeyID key_id_in, Counter counter_in);
  static Header parse(input_bytes buffer);

  input_bytes encoded() const { return _encoded; }
  size_t size() const { return _encoded.size(); }

  // Configuration byte plus 8-byte KID and CTR
  static constexpr size_t max_size = 1 + 8 + 8;

private:
  // Just the configuration byte
  static constexpr size_t min_size = 1;

  owned_bytes<max_size> _encoded;

  Header(KeyID key_id_in, Counter counter_in, input_bytes encoded_in);
};

struct KeyAndSalt
{
  static KeyAndSalt from_base_key(CipherSuite suite,
                                  KeyID key_id,
                                  input_bytes base_key);

  static constexpr size_t max_key_size = 48;
  static constexpr size_t max_salt_size = 12;

  owned_bytes<max_key_size> key;
  owned_bytes<max_salt_size> salt;
  Counter counter;
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

  void add_key(KeyID kid, input_bytes key);

  output_bytes protect(const Header& header,
                       output_bytes ciphertext,
                       input_bytes plaintext,
                       input_bytes metadata);
  output_bytes unprotect(const Header& header,
                         output_bytes ciphertext,
                         input_bytes plaintext,
                         input_bytes metadata);

  static constexpr size_t max_aad_size = Header::max_size + 512;

protected:
  CipherSuite suite;

  static constexpr size_t max_keys = 200;
  map<KeyID, KeyAndSalt, max_keys> keys;
};

// Context applies the full SFrame transform.  It tracks a counter for each key
// to ensure nonce uniqueness, adds the SFrame header on protect, and
// reads/strips the SFrame header on unprotect.
class Context : protected ContextBase
{
public:
  Context(CipherSuite suite);
  virtual ~Context();

  void add_key(KeyID kid, input_bytes key);

  output_bytes protect(KeyID key_id,
                       output_bytes ciphertext,
                       input_bytes plaintext,
                       input_bytes metadata);
  output_bytes unprotect(output_bytes plaintext,
                         input_bytes ciphertext,
                         input_bytes metadata);

protected:
  static constexpr size_t max_counters = 200;
  map<KeyID, Counter, max_counters> counters;
};

// MLSContext augments Context with logic for deriving keys from MLS.  Instead
// of adding individual keys, salts, and key IDs, the caller adds a secret for
// an epoch, and keys / salts / key IDs are derived as needed.
class MLSContext : protected Context
{
public:
  using EpochID = uint64_t;
  using SenderID = uint64_t;
  using ContextID = uint64_t;

  MLSContext(CipherSuite suite_in, size_t epoch_bits_in);

  void add_epoch(EpochID epoch_id, input_bytes sframe_epoch_secret);
  void add_epoch(EpochID epoch_id,
                 input_bytes sframe_epoch_secret,
                 size_t sender_bits);
  void purge_before(EpochID keeper);

  output_bytes protect(EpochID epoch_id,
                       SenderID sender_id,
                       output_bytes ciphertext,
                       input_bytes plaintext,
                       input_bytes metadata);
  output_bytes protect(EpochID epoch_id,
                       SenderID sender_id,
                       ContextID context_id,
                       output_bytes ciphertext,
                       input_bytes plaintext,
                       input_bytes metadata);

  output_bytes unprotect(output_bytes plaintext,
                         input_bytes ciphertext,
                         input_bytes metadata);

private:
  struct EpochKeys
  {
    static constexpr size_t max_secret_size = 64;

    EpochID full_epoch;
    owned_bytes<max_secret_size> sframe_epoch_secret;
    size_t sender_bits;
    size_t context_bits;
    uint64_t max_sender_id;
    uint64_t max_context_id;

    EpochKeys(EpochID full_epoch_in,
              input_bytes sframe_epoch_secret_in,
              size_t epoch_bits,
              size_t sender_bits_in);
    owned_bytes<max_secret_size> base_key(CipherSuite suite,
                                          SenderID sender_id) const;
  };

  void purge_epoch(EpochID epoch_id);

  KeyID form_key_id(EpochID epoch_id,
                    SenderID sender_id,
                    ContextID context_id) const;
  void ensure_key(KeyID key_id);

  const size_t epoch_bits;
  const size_t epoch_mask;

  // XXX(RLB) Make this an attribute of the class?
  static constexpr size_t max_epochs = 10;
  vector<std::optional<EpochKeys>, max_epochs> epoch_cache;
};

} // namespace sframe
