#include <doctest/doctest.h>
#include <fstream>
#include <nlohmann/json.hpp>
#include <sframe/sframe.h>

#include <crypto.h>

#include "common.h"

using namespace sframe;
using nlohmann::json;

struct HexBytes {
  bytes data;

  operator input_bytes() const { return data; }
};

// Seems redundant, but works
bool operator==(const HexBytes& hex, const input_bytes& other) {
  return input_bytes(hex) == other;
}

bool operator==(const input_bytes& other, const HexBytes& hex) {
  return hex == other;
}

void from_json(const json& j, HexBytes& b) {
  const auto hex = j.get<std::string>();

  if (hex.length() % 2 == 1) {
    throw std::invalid_argument("Odd-length hex string");
  }

  const auto len = hex.length() / 2;
  b.data.resize(len);
  for (size_t i = 0; i < len; i += 1) {
    const std::string byte = hex.substr(2 * i, 2);
    b.data.at(i) = static_cast<uint8_t>(strtol(byte.c_str(), nullptr, 16));
  }
}

void to_json(json& /* j */, const HexBytes& /* p */) {
  // Included just so that macros work
}

struct HeaderTestVector
{
  uint64_t kid;
  uint64_t ctr;
  HexBytes encoded;

  NLOHMANN_DEFINE_TYPE_INTRUSIVE(HeaderTestVector, kid, ctr, encoded)

  void verify() const {
    // Decode
    const auto decoded = Header::parse(encoded);
    REQUIRE(decoded.key_id == kid);
    REQUIRE(decoded.counter == ctr);
    REQUIRE(decoded.size() == encoded.data.size());
    REQUIRE(decoded.encoded() == encoded);

    // Encode
    const auto to_encode = Header{ kid, ctr };
    REQUIRE(to_encode.encoded() == encoded);
  }
};

struct AesCtrHmacTestVector
{
  CipherSuite cipher_suite;
  HexBytes key;
  HexBytes enc_key;
  HexBytes auth_key;
  HexBytes nonce;
  HexBytes aad;
  HexBytes pt;
  HexBytes ct;

  NLOHMANN_DEFINE_TYPE_INTRUSIVE(AesCtrHmacTestVector,
                                 cipher_suite,
                                 key,
                                 enc_key,
                                 auth_key,
                                 nonce,
                                 aad,
                                 pt,
                                 ct)

  void verify() const {
#if 0 // TODO(RLB) Re-enable after updating crypto routines to match the spec
    // Seal
    auto ciphertext = bytes(ct.data.size());
    const auto ct_out = seal(cipher_suite, key, nonce, ciphertext, aad, pt);
    REQUIRE(ct_out == ct);

    // Open
    auto plaintext = bytes(pt.data.size());
    const auto pt_out = open(cipher_suite, key, nonce, plaintext, aad, ct);
    REQUIRE(pt_out == pt);
#endif
  }
};

struct SFrameTestVector
{
  CipherSuite cipher_suite;
  uint64_t kid;
  uint64_t ctr;
  HexBytes base_key;
  HexBytes sframe_key_label;
  HexBytes sframe_salt_label;
  HexBytes sframe_secret;
  HexBytes metadata;
  HexBytes nonce;
  HexBytes aad;
  HexBytes pt;
  HexBytes ct;

  NLOHMANN_DEFINE_TYPE_INTRUSIVE(SFrameTestVector,
                                 cipher_suite,
                                 kid,
                                 ctr,
                                 base_key,
                                 sframe_key_label,
                                 sframe_salt_label,
                                 sframe_secret,
                                 metadata,
                                 nonce,
                                 aad,
                                 pt,
                                 ct)

  void verify() const {
    // TODO(RLB)
  }
};

struct TestVectors
{
  std::vector<HeaderTestVector> header;
  std::vector<AesCtrHmacTestVector> aes_ctr_hmac;
  std::vector<SFrameTestVector> sframe;

  NLOHMANN_DEFINE_TYPE_INTRUSIVE(TestVectors, header, aes_ctr_hmac, sframe)
};

struct TestVectorTest
{
  static std::unique_ptr<TestVectors> vectors;

  TestVectorTest()
  {
    if (vectors == nullptr) {
      const auto vectors_json = json::parse(std::ifstream("test-vectors.json"));
      vectors = std::make_unique<TestVectors>(vectors_json.get<TestVectors>());
    }
  }
};

std::unique_ptr<TestVectors> TestVectorTest::vectors = nullptr;

TEST_CASE_FIXTURE(TestVectorTest, "Header Test Vectors")
{
  for (const auto& tv : vectors->header) {
    tv.verify();
  }
}

TEST_CASE_FIXTURE(TestVectorTest, "AES-CTR-HMAC Test Vectors")
{
  for (const auto& tv : vectors->aes_ctr_hmac) {
    tv.verify();
  }
}

TEST_CASE_FIXTURE(TestVectorTest, "SFrame Test Vectors")
{
  for (const auto& tv : vectors->sframe) {
    tv.verify();
  }
}
