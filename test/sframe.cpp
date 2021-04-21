#include <doctest/doctest.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <sframe/sframe.h>

#include <iostream>  // for string, operator<<
#include <map>       // for map
#include <stdexcept> // for invalid_argument
#include <string>    // for basic_string, operator==

using namespace sframe;

// Use RAII to enable FIPS at the beginning of a context, and disable it again
// when the lock goes out of scope.
struct FIPSLock
{
  FIPSLock(bool enabled)
  {
    if (!enabled) {
      return;
    }

    const auto* require = std::getenv("REQUIRE_FIPS");

    auto rv = FIPS_mode_set(1);
    if (require) {
      REQUIRE(rv == 1);
    }
  }

  ~FIPSLock()
  {
    refcount -= 1;
    if (refcount == 0) {
      FIPS_mode_set(0);
    }
  }

private:
  static int refcount;
};

int FIPSLock::refcount = 0;

static bytes
from_hex(const std::string& hex)
{
  if (hex.length() % 2 == 1) {
    throw std::invalid_argument("Odd-length hex string");
  }

  auto len = int(hex.length() / 2);
  auto out = bytes(len);
  for (int i = 0; i < len; i += 1) {
    auto byte = hex.substr(2 * i, 2);
    out[i] = static_cast<uint8_t>(strtol(byte.c_str(), nullptr, 16));
  }

  return out;
}

template<typename T>
bytes
to_bytes(const T& range)
{
  return bytes(range.begin(), range.end());
}

TEST_CASE("SFrame Known-Answer")
{
  struct KnownAnswerTest
  {
    bytes key;
    bytes short_kid_ctr0;
    bytes short_kid_ctr1;
    bytes short_kid_ctr2;
    bytes long_kid_short_ctr;
    bytes long_kid_long_ctr;
  };

  const auto short_kid = KeyID(0x07);
  const auto long_kid = KeyID(0xffff);
  const auto long_ctr = KeyID(0x0100);
  const auto plaintext = from_hex("00010203");
  const std::map<CipherSuite, KnownAnswerTest> cases{
    { CipherSuite::AES_CM_128_HMAC_SHA256_4,
      {
        from_hex("101112131415161718191a1b1c1d1e1f"),
        from_hex("170023b51101e8cf3180"),
        from_hex("1701aa0743f6fed8c056"),
        from_hex("1702eae8243335f26dc9"),
        from_hex("1affff0023b51101b0927605"),
        from_hex("2affff01001981bb4f5d35ad0c"),
      } },
    { CipherSuite::AES_CM_128_HMAC_SHA256_8,
      {
        from_hex("202122232425262728292a2b2c2d2e2f"),
        from_hex("170022067e9270080090597dfadc"),
        from_hex("1701d868b21f5e80434093d12eef"),
        from_hex("170266de5b9332a80dea44a6407c"),
        from_hex("1affff0022067e92500ce44901a10eef"),
        from_hex("2affff01005ba58d1302a41630f1214e17"),
      } },
    { CipherSuite::AES_GCM_128_SHA256,
      {
        from_hex("303132333435363738393a3b3c3d3e3f"),
        from_hex("170048310f3b8c8a7297a92b3ed392938f9d0d087118"),
        from_hex("170145c8c2cd5ef5773e38f23ee6236a623f8351cfce"),
        from_hex("17021ea6e7b05246606050b44fe105f419dea85b4b7a"),
        from_hex("1affff0048310f3b542c2bc859816a10ee5f83f4f840f6e5"),
        from_hex("2affff0100f1f838df14b1e675fb0b0618291838e628fea346"),
      } },
    { CipherSuite::AES_GCM_256_SHA512,
      {
        from_hex(
          "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"),
        from_hex("1700b591faafe60c9c3a7d8dd1c18f91a72c510c8e63"),
        from_hex("1701d555e665358a2486d99ac7272bedd503f53ec9d7"),
        from_hex("170222e5fcd4709da8cc4d4a4e6e38a0b16afd0063fc"),
        from_hex("1affff00b591faafc843b5831c7fc08b477d926f8c4c8f9b"),
        from_hex("2affff01007b0e9ee905ab26c73927d7ece036a08c618610e4"),
      } },
  };

  auto pt_out = bytes(plaintext.size());
  auto ct_out = bytes(plaintext.size() + max_overhead);

  for (auto& pair : cases) {
    auto& suite = pair.first;
    auto& tc = pair.second;

    auto ctx = Context(suite);
    ctx.add_key(short_kid, tc.key);
    ctx.add_key(long_kid, tc.key);

    // KID=0x07, CTR=0, 1, 2
    auto ct0 = to_bytes(ctx.protect(short_kid, ct_out, plaintext));
    auto ct1 = to_bytes(ctx.protect(short_kid, ct_out, plaintext));
    auto ct2 = to_bytes(ctx.protect(short_kid, ct_out, plaintext));

    CHECK(ct0 == tc.short_kid_ctr0);
    CHECK(ct1 == tc.short_kid_ctr1);
    CHECK(ct2 == tc.short_kid_ctr2);

    CHECK(plaintext == to_bytes(ctx.unprotect(pt_out, ct0)));
    CHECK(plaintext == to_bytes(ctx.unprotect(pt_out, ct1)));
    CHECK(plaintext == to_bytes(ctx.unprotect(pt_out, ct2)));

    // KID=0xffff, CTR=0
    auto ctLS = to_bytes(ctx.protect(long_kid, ct_out, plaintext));
    for (Counter ctr = 1; ctr < long_ctr; ctr++) {
      ctx.protect(long_kid, ct_out, plaintext);
    }
    auto ctLL = to_bytes(ctx.protect(long_kid, ct_out, plaintext));

    CHECK(to_bytes(ctLS) == tc.long_kid_short_ctr);
    CHECK(to_bytes(ctLL) == tc.long_kid_long_ctr);

    CHECK(plaintext == to_bytes(ctx.unprotect(pt_out, ct0)));
    CHECK(plaintext == to_bytes(ctx.unprotect(pt_out, ct1)));
    CHECK(plaintext == to_bytes(ctx.unprotect(pt_out, ct2)));
  }
}

static void
sframe_round_trip(bool fips)
{
  auto fips_lock = FIPSLock(fips);

  const auto rounds = 1 << 9;
  const auto kid = KeyID(0x42);
  const auto plaintext = from_hex("00010203");
  const std::map<CipherSuite, bytes> keys{
    { CipherSuite::AES_CM_128_HMAC_SHA256_4,
      from_hex("101112131415161718191a1b1c1d1e1f") },
    { CipherSuite::AES_CM_128_HMAC_SHA256_8,
      from_hex("202122232425262728292a2b2c2d2e2f") },
    { CipherSuite::AES_GCM_128_SHA256,
      from_hex("303132333435363738393a3b3c3d3e3f") },
    { CipherSuite::AES_GCM_256_SHA512,
      from_hex("404142434445464748494a4b4c4d4e4f"
               "505152535455565758595a5b5c5d5e5f") },
  };

  auto pt_out = bytes(plaintext.size());
  auto ct_out = bytes(plaintext.size() + max_overhead);

  for (auto& pair : keys) {
    auto& suite = pair.first;
    auto& key = pair.second;

    auto send = Context(suite);
    send.add_key(kid, key);

    auto recv = Context(suite);
    recv.add_key(kid, key);

    for (int i = 0; i < rounds; i++) {
      auto encrypted = to_bytes(send.protect(kid, ct_out, plaintext));
      auto decrypted = to_bytes(recv.unprotect(pt_out, encrypted));
      CHECK(decrypted == plaintext);
    }
  }
}

TEST_CASE("SFrame Round-Trip")
{
  sframe_round_trip(false);
}
TEST_CASE("SFrame Round-Trip (FIPS)")
{
  sframe_round_trip(true);
}

TEST_CASE("MLS Known-Answer")
{
  struct KnownAnswerTest
  {
    using Epoch = std::vector<bytes>;
    std::vector<Epoch> epochs;
  };

  const auto plaintext = from_hex("00010203");
  const auto epoch_bits = 4;
  const auto epoch_ids = std::vector<MLSContext::EpochID>{
    0x00,
    0x0f,
    0x10,
  };
  const auto epoch_secrets = std::vector<bytes>{
    from_hex("00000000000000000000000000000000"),
    from_hex("0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f"),
    from_hex("10101010101010101010101010101010"),
  };
  const auto sender_ids = std::vector<MLSContext::SenderID>{
    0x0a,
    0xaa,
    0xaaa,
  };
  const std::map<CipherSuite, KnownAnswerTest> cases{
    { CipherSuite::AES_CM_128_HMAC_SHA256_4,
      { {
        {
          from_hex("19a000c92bf2b7e7ff7380"),
          from_hex("1a0aa000c84890cf05de8f15"),
          from_hex("1aaaa0004361be8cdb7110ae"),
        },
        {
          from_hex("19af0086adc8a84a84eca2"),
          from_hex("1a0aaf006870557d8f7c5a27"),
          from_hex("1aaaaf00a0e68b606087812a"),
        },
        {
          from_hex("19a0001ad5829bbc85f504"),
          from_hex("1a0aa0004769a13c89e6ba00"),
          from_hex("1aaaa000586b97fa780a731a"),
        },
      } } },
    { CipherSuite::AES_CM_128_HMAC_SHA256_8,
      { {
        {
          from_hex("19a000c92bf2b7e7ff7380241209e1"),
          from_hex("1a0aa000c84890cf05de8f15e2a6a98b"),
          from_hex("1aaaa0004361be8cdb7110aed8f39907"),
        },
        {
          from_hex("19af0086adc8a84a84eca293b60fbf"),
          from_hex("1a0aaf006870557d8f7c5a27fe48227b"),
          from_hex("1aaaaf00a0e68b606087812a9034f06a"),
        },
        {
          from_hex("19a0001ad5829bbc85f504f77f3dc8"),
          from_hex("1a0aa0004769a13c89e6ba005f2cfe5a"),
          from_hex("1aaaa000586b97fa780a731a435006cd"),
        },
      } } },
    { CipherSuite::AES_GCM_128_SHA256,
      { {
        {
          from_hex("19a000bb7d6b3b9a9a5f1abc476b5cfaff53a9c3685ad5"),
          from_hex("1a0aa000382032d06913e59807a6ad0f6193dca0ab8b6ceb"),
          from_hex("1aaaa0006aa1aa44edf64dd101a31d9f39cd1abe129de1ed"),
        },
        {
          from_hex("19af0077d06820762dfc682df9e0f3bd635b6240840359"),
          from_hex("1a0aaf00a99857f0b13b2b8b44923c54655494d8270b07a8"),
          from_hex("1aaaaf00662bf029c244947f2a8cefa3512259a3aff92dd0"),
        },
        {
          from_hex("19a0000661fb1fa3c7bd98032ab3aaea3c1ff4897324fa"),
          from_hex("1a0aa0008140a14b320f01830bce39727dc17a29e8e08fb7"),
          from_hex("1aaaa00084da92db90a3a24032a12c2706b90a79327f66fb"),
        },
      } } },
    { CipherSuite::AES_GCM_256_SHA512,
      { {
        {
          from_hex("19a000414462cce78dc5e70db0edb825fdccdb27e0a8f8"),
          from_hex("1a0aa000c013c6d9609e398adb51aa2df988ab2090615217"),
          from_hex("1aaaa0009a2a9ab0db57883851ab7d4eb57355cd950e4819"),
        },
        {
          from_hex("19af00466bc33bfe97e91602724b243b90c9a1dcb85416"),
          from_hex("1a0aaf00f72194872e6a76fcce1a4ca71d4e0e5a48017c67"),
          from_hex("1aaaaf0043a23ff519b65803318cfc7f661021e18ff19e68"),
        },
        {
          from_hex("19a0004f4d239d117be8ab84e9972868016258b8a9a65f"),
          from_hex("1a0aa000b592b5e30ce07c102c5ee18fcb99e19be76c7739"),
          from_hex("1aaaa000fd95ba9a9ab3d82e9efce294a75837d766f75526"),
        },
      } } },
  };

  auto pt_out = bytes(plaintext.size());
  auto ct_out = bytes(plaintext.size() + max_overhead);

  for (const auto& pair : cases) {
    auto& suite = pair.first;
    auto& tc = pair.second;

    auto ctx = MLSContext(suite, epoch_bits);

    CHECK(tc.epochs.size() == epoch_ids.size());
    for (size_t i = 0; i < tc.epochs.size(); i++) {
      ctx.add_epoch(epoch_ids[i], epoch_secrets[i]);

      CHECK(tc.epochs[i].size() == sender_ids.size());
      for (size_t j = 0; j < tc.epochs[i].size(); j++) {
        auto encrypted =
          ctx.protect(epoch_ids[i], sender_ids[j], ct_out, plaintext);
        CHECK(tc.epochs[i][j] == to_bytes(encrypted));

        auto decrypted = ctx.unprotect(pt_out, tc.epochs[i][j]);
        CHECK(plaintext == to_bytes(decrypted));
      }
    }
  }
}

static void
mls_round_trip(bool fips)
{
  auto fips_lock = FIPSLock(fips);

  const auto epoch_bits = 2;
  const auto test_epochs = 1 << (epoch_bits + 1);
  const auto epoch_rounds = 10;
  const auto plaintext = from_hex("00010203");
  const auto sender_id_a = MLSContext::SenderID(0xA0A0A0A0);
  const auto sender_id_b = MLSContext::SenderID(0xA1A1A1A1);
  const std::vector<CipherSuite> suites{
    CipherSuite::AES_CM_128_HMAC_SHA256_4,
    CipherSuite::AES_CM_128_HMAC_SHA256_8,
    CipherSuite::AES_GCM_128_SHA256,
    CipherSuite::AES_GCM_256_SHA512,
  };

  auto pt_out = bytes(plaintext.size());
  auto ct_out = bytes(plaintext.size() + max_overhead);

  for (auto& suite : suites) {
    auto member_a = MLSContext(suite, epoch_bits);
    auto member_b = MLSContext(suite, epoch_bits);

    for (MLSContext::EpochID epoch_id = 0; epoch_id < test_epochs; epoch_id++) {
      const auto sframe_epoch_secret = bytes(8, uint8_t(epoch_id));

      member_a.add_epoch(epoch_id, sframe_epoch_secret);
      member_b.add_epoch(epoch_id, sframe_epoch_secret);

      for (int i = 0; i < epoch_rounds; i++) {
        auto encrypted_ab =
          member_a.protect(epoch_id, sender_id_a, ct_out, plaintext);
        auto decrypted_ab = member_b.unprotect(pt_out, encrypted_ab);
        CHECK(plaintext == to_bytes(decrypted_ab));

        auto encrypted_ba =
          member_b.protect(epoch_id, sender_id_b, ct_out, plaintext);
        auto decrypted_ba = member_a.unprotect(pt_out, encrypted_ba);
        CHECK(plaintext == to_bytes(decrypted_ba));
      }
    }
  }
}

TEST_CASE("MLS Round-Trip")
{
  mls_round_trip(false);
}
TEST_CASE("MLS Round-Trip (FIPS)")
{
  mls_round_trip(true);
}

TEST_CASE("MLS Failure after Purge")
{
  const auto suite = CipherSuite::AES_GCM_128_SHA256;
  const auto epoch_bits = 2;
  const auto plaintext = from_hex("00010203");
  const auto sender_id_a = MLSContext::SenderID(0xA0A0A0A0);
  const auto sframe_epoch_secret_1 = bytes(32, 1);
  const auto sframe_epoch_secret_2 = bytes(32, 2);

  auto pt_out = bytes(plaintext.size());
  auto ct_out = bytes(plaintext.size() + max_overhead);

  auto member_a = MLSContext(suite, epoch_bits);
  auto member_b = MLSContext(suite, epoch_bits);

  // Install epoch 1 and create a cipihertext
  const auto epoch_id_1 = MLSContext::EpochID(1);
  member_a.add_epoch(epoch_id_1, sframe_epoch_secret_1);
  member_b.add_epoch(epoch_id_1, sframe_epoch_secret_1);

  const auto enc_ab_1 =
    member_a.protect(epoch_id_1, sender_id_a, ct_out, plaintext);
  const auto enc_ab_1_data = to_bytes(enc_ab_1);

  // Install epoch 2
  const auto epoch_id_2 = MLSContext::EpochID(2);
  member_a.add_epoch(epoch_id_2, sframe_epoch_secret_2);
  member_b.add_epoch(epoch_id_2, sframe_epoch_secret_2);

  // Purge epoch 1 and verify failure
  member_a.purge_before(epoch_id_2);
  member_b.purge_before(epoch_id_2);

  CHECK_THROWS_AS(member_a.protect(epoch_id_1, sender_id_a, ct_out, plaintext),
                  invalid_parameter_error);
  CHECK_THROWS_AS(member_b.unprotect(pt_out, enc_ab_1_data),
                  invalid_parameter_error);

  const auto enc_ab_2 =
    member_a.protect(epoch_id_2, sender_id_a, ct_out, plaintext);
  const auto dec_ab_2 = member_b.unprotect(pt_out, enc_ab_2);
  CHECK(plaintext == to_bytes(dec_ab_2));
}
