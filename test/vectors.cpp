#include <doctest/doctest.h>
#include <nlohmann/json.hpp>
#include <sframe/sframe.h>
#include <fstream>

using namespace sframe;
using nlohmann::json;

struct HeaderTestVector
{
  uint64_t kid;
  uint64_t ctr;
  bytes encoded;

  NLOHMANN_DEFINE_TYPE_INTRUSIVE(HeaderTestVector, kid, ctr, encoded)
};

struct AesCtrHmacTestVector
{
  CipherSuite cipher_suite;
  bytes key;
  bytes enc_key;
  bytes auth_key;
  bytes nonce;
  bytes aad;
  bytes pt;
  bytes ct;

  NLOHMANN_DEFINE_TYPE_INTRUSIVE(AesCtrHmacTestVector,
                                 cipher_suite,
                                 key,
                                 enc_key,
                                 auth_key,
                                 nonce,
                                 aad,
                                 pt,
                                 ct)
};

struct SFrameTestVector
{
  CipherSuite cipher_suite;
  uint64_t kid;
  uint64_t ctr;
  bytes base_key;
  bytes sframe_key_label;
  bytes sframe_salt_label;
  bytes sframe_secret;
  bytes metadata;
  bytes nonce;
  bytes aad;
  bytes pt;
  bytes ct;

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
  // TODO
}
