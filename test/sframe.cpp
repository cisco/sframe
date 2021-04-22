#include <doctest/doctest.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <sframe/sframe.h>

#include <map>       // for map
#include <stdexcept> // for invalid_argument
#include <string>    // for basic_string, operator==

using namespace sframe;

static void
ensure_fips_if_required()
{
  const auto* require = std::getenv("REQUIRE_FIPS");
  if (require && FIPS_mode() == 0) {
    REQUIRE(FIPS_mode_set(1) == 1);
  }
}

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
  ensure_fips_if_required();

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
        from_hex("070023b51101cc7ebc3d"),
        from_hex("0701aa0743f6aa3a2b9b"),
        from_hex("0702eae82433853983b7"),
        from_hex("0affff0023b51101efb2441d"),
        from_hex("1affff01001981bb4f7281d098"),
      } },
    { CipherSuite::AES_CM_128_HMAC_SHA256_8,
      {
        from_hex("202122232425262728292a2b2c2d2e2f"),
        from_hex("070022067e92bbacd94627c087b8"),
        from_hex("0701d868b21f4ba897d19490eaa5"),
        from_hex("070266de5b93b640ba637ae569dc"),
        from_hex("0affff0022067e92dac1fe9af8fd6a07"),
        from_hex("1affff01005ba58d136415a9799dc921f9"),
      } },
    { CipherSuite::AES_GCM_128_SHA256,
      {
        from_hex("303132333435363738393a3b3c3d3e3f"),
        from_hex("070048310f3bb26f3ee3ceed7756efe2f32078766c56"),
        from_hex("070145c8c2cd60103b4a5f3477635e1b1e82f62fd280"),
        from_hex("07021ea6e7b06ca32c143772066478856563dd255634"),
        from_hex("0affff0048310f3b6ac967bc3e472395932eff498d3eebab"),
        from_hex("1affff0100f1f838df579e32e95341dc97ae8bbd21b77c8494"),
      } },
    { CipherSuite::AES_GCM_256_SHA512,
      {
        from_hex(
          "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"),
        from_hex("0700b591faaff9b9965fcabfd0949a2bb67be4179753"),
        from_hex("0701d555e6652a3f2ee36ea8c6723e57c4544025d0e7"),
        from_hex("070222e5fcd46f28a2a9fa784f3b2d1aa03d481b7acc"),
        from_hex("0affff00b591faafd7f6bfe6ab4dc1de52c78338395796ab"),
        from_hex("1affff01007b0e9ee925743869e071d413def89374beab3bb4"),
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

TEST_CASE("SFrame Round-Trip")
{
  ensure_fips_if_required();

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

TEST_CASE("MLS Known-Answer")
{
  ensure_fips_if_required();

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
          from_hex("09a000c92bf2b7154e0356"),
          from_hex("0a0aa000c84890cf4a814ce0"),
          from_hex("0aaaa0004361be8c2c549ae5"),
        },
        {
          from_hex("09af0086adc8a87988307c"),
          from_hex("0a0aaf006870557dd62e9409"),
          from_hex("0aaaaf00a0e68b60eab24b27"),
        },
        {
          from_hex("09a0001ad5829b23a11c33"),
          from_hex("0a0aa0004769a13c95568e30"),
          from_hex("0aaaa000586b97fa7f7fe096"),
        },
      } } },
    { CipherSuite::AES_CM_128_HMAC_SHA256_8,
      { {
        {
          from_hex("09a000c92bf2b7154e0356b4be009e"),
          from_hex("0a0aa000c84890cf4a814ce031fae9f7"),
          from_hex("0aaaa0004361be8c2c549ae53384b5f1"),
        },
        {
          from_hex("09af0086adc8a87988307c147e8138"),
          from_hex("0a0aaf006870557dd62e94097fdfaae8"),
          from_hex("0aaaaf00a0e68b60eab24b275b63f964"),
        },
        {
          from_hex("09a0001ad5829b23a11c33a5ac2f11"),
          from_hex("0a0aa0004769a13c95568e30f9bafee2"),
          from_hex("0aaaa000586b97fa7f7fe0965aee99da"),
        },
      } } },
    { CipherSuite::AES_GCM_128_SHA256,
      { {
        {
          from_hex("09a000bb7d6b3b4f32219f00516841cca349101f942ba1"),
          from_hex("0a0aa000382032d088cb627c73b2c55968092d7039538f02"),
          from_hex("0aaaa0006aa1aa44bbd1911b07ad876350c29790dad1fa04"),
        },
        {
          from_hex("09af0077d0682046fdb1e08315c63b6c5f9f205a9e76c4"),
          from_hex("0a0aaf00a99857f0a8aa0b2d0b5825ea2c0d71621f2bb7aa"),
          from_hex("0aaaaf00662bf029595d34ea58a68edc7390c78e0fcc6de4"),
        },
        {
          from_hex("09a0000661fb1f7b2b2dd820b225f5239cafc817da7821"),
          from_hex("0a0aa0008140a14bb80a6d5793637d820de7c01df4f7f676"),
          from_hex("0aaaa00084da92dbd31c174d3d7423c9470a48849c5c83b3"),
        },
      } } },
    { CipherSuite::AES_GCM_256_SHA512,
      { {
        {
          from_hex("09a000414462ccdfcb5473b8e0e4f686362e35a2985182"),
          from_hex("0a0aa000c013c6d92f0683dbf87ccca3c2c11d3eca3c382f"),
          from_hex("0aaaa0009a2a9ab03c3eca040928d8ef17ea531696b8163a"),
        },
        {
          from_hex("09af00466bc33b10ec4405e4ff7241d11c63b21192b535"),
          from_hex("0a0aaf00f7219487f1bf6ccec5c40888bcd79bb135900e02"),
          from_hex("0aaaaf0043a23ff53ae88f41084ad503f1ec82613983b00b"),
        },
        {
          from_hex("09a0004f4d239d260255899228d119099fa23f09d8b880"),
          from_hex("0a0aa000b592b5e3bc31c7ac13eea1e69e83826233f90a4d"),
          from_hex("0aaaa000fd95ba9acefc244e4652db355d4ce0a5c5137492"),
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

TEST_CASE("MLS Round-Trip")
{
  ensure_fips_if_required();

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

TEST_CASE("MLS Failure after Purge")
{
  ensure_fips_if_required();

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
