#include <doctest/doctest.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <sframe/sframe.h>

#include "common.h"

#include <iostream>
#include <map>       // for map
#include <stdexcept> // for invalid_argument
#include <string>    // for basic_string, operator==

using namespace SFRAME_NAMESPACE;

TEST_CASE("SFrame Round-Trip")
{
  const auto rounds = 1 << 9;
  const auto kid = KeyID(0x42);
  const auto plaintext = from_hex("00010203");
  const std::map<CipherSuite, bytes> keys{
    { CipherSuite::AES_128_CTR_HMAC_SHA256_80,
      from_hex("000102030405060708090a0b0c0d0e0f") },
    { CipherSuite::AES_128_CTR_HMAC_SHA256_80,
      from_hex("101112131415161718191a1b1c1d1e1f") },
    { CipherSuite::AES_128_CTR_HMAC_SHA256_80,
      from_hex("202122232425262728292a2b2c2d2e2f") },
    { CipherSuite::AES_GCM_128_SHA256,
      from_hex("303132333435363738393a3b3c3d3e3f") },
    { CipherSuite::AES_GCM_256_SHA512,
      from_hex("404142434445464748494a4b4c4d4e4f"
               "505152535455565758595a5b5c5d5e5f") },
  };

  auto pt_out = bytes(plaintext.size());
  auto ct_out = bytes(plaintext.size() + Context::max_overhead);

  for (auto& pair : keys) {
    auto& suite = pair.first;
    auto& key = pair.second;

    auto send = Context(suite);
    send.add_key(kid, KeyUsage::protect, key);

    auto recv = Context(suite);
    recv.add_key(kid, KeyUsage::unprotect, key);

    for (int i = 0; i < rounds; i++) {
      auto protect_result = send.protect(kid, ct_out, plaintext, {});
      REQUIRE(protect_result.is_ok());
      auto encrypted = to_bytes(protect_result.MoveValue());
      auto unprotect_result = recv.unprotect(pt_out, encrypted, {});
      REQUIRE(unprotect_result.is_ok());
      auto decrypted = to_bytes(unprotect_result.MoveValue());
      CHECK(decrypted == plaintext);
    }
  }
}

// The MLS-based key derivation isn't covered by the RFC test vectors.  So we
// only have round-trip tests, not known-answer tests.
TEST_CASE("MLS Round-Trip")
{
  const auto epoch_bits = 2;
  const auto test_epochs = 1 << (epoch_bits + 1);
  const auto epoch_rounds = 10;
  const auto metadata = from_hex("00010203");
  const auto plaintext = from_hex("04050607");
  const auto sender_id_a = MLSContext::SenderID(0xA0A0A0A0);
  const auto sender_id_b = MLSContext::SenderID(0xA1A1A1A1);
  const std::vector<CipherSuite> suites{
    CipherSuite::AES_128_CTR_HMAC_SHA256_80,
    CipherSuite::AES_128_CTR_HMAC_SHA256_64,
    CipherSuite::AES_128_CTR_HMAC_SHA256_32,
    CipherSuite::AES_GCM_128_SHA256,
    CipherSuite::AES_GCM_256_SHA512,
  };

  auto pt_out = bytes(plaintext.size());
  auto ct_out = bytes(plaintext.size() + Context::max_overhead);

  for (auto& suite : suites) {
    auto member_a = MLSContext(suite, epoch_bits);
    auto member_b = MLSContext(suite, epoch_bits);

    for (MLSContext::EpochID epoch_id = 0; epoch_id < test_epochs; epoch_id++) {
      const auto sframe_epoch_secret = bytes(8, uint8_t(epoch_id));

      member_a.add_epoch(epoch_id, sframe_epoch_secret);
      member_b.add_epoch(epoch_id, sframe_epoch_secret);

      for (int i = 0; i < epoch_rounds; i++) {
        auto protect_result_ab =
          member_a.protect(epoch_id, sender_id_a, ct_out, plaintext, metadata);
        REQUIRE(protect_result_ab.is_ok());
        auto encrypted_ab = protect_result_ab.MoveValue();
        auto unprotect_result_ab = member_b.unprotect(pt_out, encrypted_ab, metadata);
        REQUIRE(unprotect_result_ab.is_ok());
        auto decrypted_ab = unprotect_result_ab.MoveValue();
        CHECK(plaintext == to_bytes(decrypted_ab));

        auto protect_result_ba =
          member_b.protect(epoch_id, sender_id_b, ct_out, plaintext, metadata);
        REQUIRE(protect_result_ba.is_ok());
        auto encrypted_ba = protect_result_ba.MoveValue();
        auto unprotect_result_ba = member_a.unprotect(pt_out, encrypted_ba, metadata);
        REQUIRE(unprotect_result_ba.is_ok());
        auto decrypted_ba = unprotect_result_ba.MoveValue();
        CHECK(plaintext == to_bytes(decrypted_ba));
      }
    }
  }
}

TEST_CASE("MLS Round-Trip with context")
{
  const auto epoch_bits = 4;
  const auto test_epochs = 1 << (epoch_bits + 1);
  const auto epoch_rounds = 10;
  const auto metadata = from_hex("00010203");
  const auto plaintext = from_hex("04050607");
  const auto sender_id_a = MLSContext::SenderID(0xA0A0A0A0);
  const auto sender_id_b = MLSContext::SenderID(0xA1A1A1A1);
  const auto sender_id_bits = size_t(32);
  const auto context_id_0 = 0xB0B0;
  const auto context_id_1 = 0xB1B1;

  const std::vector<CipherSuite> suites{
    CipherSuite::AES_128_CTR_HMAC_SHA256_80,
    CipherSuite::AES_128_CTR_HMAC_SHA256_64,
    CipherSuite::AES_128_CTR_HMAC_SHA256_32,
    CipherSuite::AES_GCM_128_SHA256,
    CipherSuite::AES_GCM_256_SHA512,
  };

  auto pt_out = bytes(plaintext.size());
  auto ct_out_1 = bytes(plaintext.size() + Context::max_overhead);
  auto ct_out_0 = bytes(plaintext.size() + Context::max_overhead);

  for (auto& suite : suites) {
    auto member_a_0 = MLSContext(suite, epoch_bits);
    auto member_a_1 = MLSContext(suite, epoch_bits);
    auto member_b = MLSContext(suite, epoch_bits);

    for (MLSContext::EpochID epoch_id = 0; epoch_id < test_epochs; epoch_id++) {
      const auto sframe_epoch_secret = bytes(8, uint8_t(epoch_id));

      member_a_0.add_epoch(epoch_id, sframe_epoch_secret, sender_id_bits);
      member_a_1.add_epoch(epoch_id, sframe_epoch_secret, sender_id_bits);
      member_b.add_epoch(epoch_id, sframe_epoch_secret);

      for (int i = 0; i < epoch_rounds; i++) {
        auto protect_result_ab_0 = member_a_0.protect(
          epoch_id, sender_id_a, context_id_0, ct_out_0, plaintext, metadata);
        REQUIRE(protect_result_ab_0.is_ok());
        auto encrypted_ab_0 = protect_result_ab_0.MoveValue();
        auto unprotect_result_ab_0 = member_b.unprotect(pt_out, encrypted_ab_0, metadata);
        REQUIRE(unprotect_result_ab_0.is_ok());
        auto decrypted_ab_0 = to_bytes(unprotect_result_ab_0.MoveValue());
        CHECK(plaintext == decrypted_ab_0);

        auto protect_result_ab_1 = member_a_1.protect(
          epoch_id, sender_id_a, context_id_1, ct_out_1, plaintext, metadata);
        REQUIRE(protect_result_ab_1.is_ok());
        auto encrypted_ab_1 = protect_result_ab_1.MoveValue();
        auto unprotect_result_ab_1 = member_b.unprotect(pt_out, encrypted_ab_1, metadata);
        REQUIRE(unprotect_result_ab_1.is_ok());
        auto decrypted_ab_1 = to_bytes(unprotect_result_ab_1.MoveValue());
        CHECK(plaintext == decrypted_ab_1);

        CHECK(to_bytes(encrypted_ab_0) != to_bytes(encrypted_ab_1));

        auto protect_result_ba = member_b.protect(
          epoch_id, sender_id_b, ct_out_0, plaintext, metadata);
        REQUIRE(protect_result_ba.is_ok());
        auto encrypted_ba = protect_result_ba.MoveValue();
        auto unprotect_result_ba_0 = member_a_0.unprotect(pt_out, encrypted_ba, metadata);
        REQUIRE(unprotect_result_ba_0.is_ok());
        auto decrypted_ba_0 = to_bytes(unprotect_result_ba_0.MoveValue());
        auto unprotect_result_ba_1 = member_a_1.unprotect(pt_out, encrypted_ba, metadata);
        REQUIRE(unprotect_result_ba_1.is_ok());
        auto decrypted_ba_1 = to_bytes(unprotect_result_ba_1.MoveValue());
        CHECK(plaintext == decrypted_ba_0);
        CHECK(plaintext == decrypted_ba_1);
      }
    }
  }
}

TEST_CASE("MLS Failure after Purge")
{
  const auto suite = CipherSuite::AES_GCM_128_SHA256;
  const auto epoch_bits = 2;
  const auto metadata = from_hex("00010203");
  const auto plaintext = from_hex("04050607");
  const auto sender_id_a = MLSContext::SenderID(0xA0A0A0A0);
  const auto sframe_epoch_secret_1 = bytes(32, 1);
  const auto sframe_epoch_secret_2 = bytes(32, 2);

  auto pt_out = bytes(plaintext.size());
  auto ct_out = bytes(plaintext.size() + Context::max_overhead);

  auto member_a = MLSContext(suite, epoch_bits);
  auto member_b = MLSContext(suite, epoch_bits);

  // Install epoch 1 and create a cipihertext
  const auto epoch_id_1 = MLSContext::EpochID(1);
  member_a.add_epoch(epoch_id_1, sframe_epoch_secret_1);
  member_b.add_epoch(epoch_id_1, sframe_epoch_secret_1);

  const auto protect_result_ab_1 =
    member_a.protect(epoch_id_1, sender_id_a, ct_out, plaintext, metadata);
  REQUIRE(protect_result_ab_1.is_ok());
  const auto enc_ab_1 = protect_result_ab_1.value();
  const auto enc_ab_1_data = to_bytes(enc_ab_1);

  // Install epoch 2
  const auto epoch_id_2 = MLSContext::EpochID(2);
  member_a.add_epoch(epoch_id_2, sframe_epoch_secret_2);
  member_b.add_epoch(epoch_id_2, sframe_epoch_secret_2);

  // Purge epoch 1 and verify failure
  member_a.purge_before(epoch_id_2);
  member_b.purge_before(epoch_id_2);

  const auto protect_result_after_purge_1 =
    member_a.protect(epoch_id_1, sender_id_a, ct_out, plaintext, metadata);
  CHECK(!protect_result_after_purge_1.is_ok());
  CHECK(protect_result_after_purge_1.error().type() == SFrameErrorType::invalid_parameter_error);
  
  auto unprotect_result_after_purge = member_b.unprotect(pt_out, enc_ab_1_data, metadata);
  CHECK(!unprotect_result_after_purge.is_ok());
  CHECK(unprotect_result_after_purge.error().type() == SFrameErrorType::invalid_parameter_error);

  const auto protect_result_ab_2 =
    member_a.protect(epoch_id_2, sender_id_a, ct_out, plaintext, metadata);
  REQUIRE(protect_result_ab_2.is_ok());
  const auto enc_ab_2 = protect_result_ab_2.value();
  auto unprotect_result_ab_2 = member_b.unprotect(pt_out, enc_ab_2, metadata);
  REQUIRE(unprotect_result_ab_2.is_ok());
  const auto dec_ab_2 = unprotect_result_ab_2.MoveValue();
  CHECK(plaintext == to_bytes(dec_ab_2));
}
