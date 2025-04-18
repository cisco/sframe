#include <doctest/doctest.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <sframe/sframe.h>

#include <iostream>
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

/*
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
*/

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

#if 0
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
          from_hex("09a000a099f9cfcebe0016"),
          from_hex("0a0aa000102ea6af868bda78"),
          from_hex("0aaaa0009c0aa3c3dc43d075"),
        },
        {
          from_hex("09af008414bb5861dec7d0"),
          from_hex("0a0aaf004486695c578d1d7b"),
          from_hex("0aaaaf00da9a202a28d52f29"),
        },
        {
          from_hex("09a0008f7b4591e6f1bc5b"),
          from_hex("0a0aa00039743979f1e9e9f5"),
          from_hex("0aaaa000658794f1db8a4553"),
        },
      } } },
    { CipherSuite::AES_CM_128_HMAC_SHA256_8,
      { {
        {
          from_hex("09a000a099f9cfcebe0016ec6d4089"),
          from_hex("0a0aa000102ea6af868bda7839a896e4"),
          from_hex("0aaaa0009c0aa3c3dc43d07567ed7c50"),
        },
        {
          from_hex("09af008414bb5861dec7d0e1e2bc71"),
          from_hex("0a0aaf004486695c578d1d7b90e9b557"),
          from_hex("0aaaaf00da9a202a28d52f29f4bf0ddf"),
        },
        {
          from_hex("09a0008f7b4591e6f1bc5bd3568ba2"),
          from_hex("0a0aa00039743979f1e9e9f57e4a5553"),
          from_hex("0aaaa000658794f1db8a45534bfde555"),
        },
      } } },
    { CipherSuite::AES_GCM_128_SHA256,
      { {
        {
          from_hex("09a000f32e41cdb15b8c9c3bd57e4ed008f056fa263df3"),
          from_hex("0a0aa000ad96fdf39faf8711d53279f8549ad4fb23f1f8aa"),
          from_hex("0aaaa000c79771b0d97bf9035b920fb1bb565c4025cf8a47"),
        },
        {
          from_hex("09af00feb0c2b242d3c8a9aec464fc92f55c9539d5caa8"),
          from_hex("0a0aaf00c0afce4867ee782c45de14a1990ea5576f41fa52"),
          from_hex("0aaaaf00d034912de869721e8ea2e5724d3eb69f4b7c7e6a"),
        },
        {
          from_hex("09a00003fa0e4e4c36bc0aed031c56b1db488c525831b3"),
          from_hex("0a0aa000184a009fdfa7d0ee2c36a9e9ee1d21663b4dcde1"),
          from_hex("0aaaa0008f2e842d16d4ec69b23623b7bd9838e4f906bab1"),
        },
      } } },
    { CipherSuite::AES_GCM_256_SHA512,
      { {
        {
          from_hex("09a0007878e804d643a86c6ec1711ee2b6a9e6aa4d9be8"),
          from_hex("0a0aa00083f5083c175e74c484d837e35d6e359ef5dfc66a"),
          from_hex("0aaaa0000144a05a1c3c75691b5597d01d1517d5ebc92460"),
        },
        {
          from_hex("09af002a2be564b2a788abd838f01cfcec315563bdf708"),
          from_hex("0a0aaf00ca411f242081522129078b6c5239f5e8baf10d67"),
          from_hex("0aaaaf0011a1a4ea5a7796589931acc62c3a6ccf5008e3cc"),
        },
        {
          from_hex("09a0003f5d9b66df64c7cb3cce99952028990a3869d3a8"),
          from_hex("0a0aa0000b8a680c5bfc4efb8fb68041b5f63441e9aaaa85"),
          from_hex("0aaaa00061c7c6a5b2882f037aea330533e0381d1f25e074"),
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
        std::cout << tc.epochs[i][j] << " " << to_bytes(encrypted) << std::endl;
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

        std::cout << encrypted_ab << std::endl;

        auto encrypted_ba =
          member_b.protect(epoch_id, sender_id_b, ct_out, plaintext);
        auto decrypted_ba = member_a.unprotect(pt_out, encrypted_ba);
        CHECK(plaintext == to_bytes(decrypted_ba));
      }
    }
  }
}

TEST_CASE("MLS Known-Answer with Context")
{
  ensure_fips_if_required();

  struct KnownAnswerTest
  {
    using ContextCases = std::vector<bytes>;
    using SenderCases = std::vector<ContextCases>;
    std::vector<SenderCases> epochs;
  };

  const auto plaintext = from_hex("00010203");
  const auto epoch_bits = 4;
  // const auto sender_bits = 12;
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
  const auto context_ids = std::vector<MLSContext::ContextID>{
    0x0b,
    0xbb,
    0xbbb,
  };
  const auto sender_bits = 12;
  const std::map<CipherSuite, KnownAnswerTest> cases{
    { CipherSuite::AES_CM_128_HMAC_SHA256_4,
      { {
        {
          {
            from_hex("0b0b00a000e78b66f2396ad3fb"),
            from_hex("0bbb00a000627f7a610c7d5114"),
            from_hex("0c0bbb00a000010247612644e928"),
          },
          {
            from_hex("0b0b0aa000065aacf40d149781"),
            from_hex("0bbb0aa0003db4ff6316a3b4aa"),
            from_hex("0c0bbb0aa000804e43f1e3b30c01"),
          },
          {
            from_hex("0b0baaa0008ee32c082a6baced"),
            from_hex("0bbbaaa000d158bf21f2be0aff"),
            from_hex("0c0bbbaaa000ddb84e167700afcb"),
          },
        },
        {
          {
            from_hex("0b0b00af00645a02cbd4dd5469"),
            from_hex("0bbb00af00436630a155d66c9e"),
            from_hex("0c0bbb00af000160419ebc8f5181"),
          },
          {
            from_hex("0b0b0aaf009c1c9c9a6103a004"),
            from_hex("0bbb0aaf003f0045b076151853"),
            from_hex("0c0bbb0aaf00e638bf4dbafe35dc"),
          },
          {
            from_hex("0b0baaaf002c21652122601e05"),
            from_hex("0bbbaaaf001a40ca810397ca64"),
            from_hex("0c0bbbaaaf00cbdcb9e4e401ee56"),
          },
        },
        {
          {
            from_hex("0b0b00a000dadd1533c0418d7a"),
            from_hex("0bbb00a000144ac3cfd5e4a563"),
            from_hex("0c0bbb00a000b753901426810fcd"),
          },
          {
            from_hex("0b0b0aa00006be6cd4471e3028"),
            from_hex("0bbb0aa0008cea2fb844ed6440"),
            from_hex("0c0bbb0aa000ad1376f533ebf44a"),
          },
          {
            from_hex("0b0baaa000a20b1f3ed8499f8a"),
            from_hex("0bbbaaa0006f311c5a7aaf0289"),
            from_hex("0c0bbbaaa000ede89b44263ee250"),
          },
        },
      } } },
    { CipherSuite::AES_CM_128_HMAC_SHA256_8,
      { {
        {
          {
            from_hex("0b0b00a000e78b66f2396ad3fbb4a56007"),
            from_hex("0bbb00a000627f7a610c7d51149811b320"),
            from_hex("0c0bbb00a000010247612644e9287540ce73"),
          },
          {
            from_hex("0b0b0aa000065aacf40d14978172ebf918"),
            from_hex("0bbb0aa0003db4ff6316a3b4aadd53d398"),
            from_hex("0c0bbb0aa000804e43f1e3b30c0197cfd76b"),
          },
          {
            from_hex("0b0baaa0008ee32c082a6baced795e34b5"),
            from_hex("0bbbaaa000d158bf21f2be0affa7f4a66d"),
            from_hex("0c0bbbaaa000ddb84e167700afcbc8d2fe11"),
          },
        },
        {
          {
            from_hex("0b0b00af00645a02cbd4dd546959a200ef"),
            from_hex("0bbb00af00436630a155d66c9e16890d09"),
            from_hex("0c0bbb00af000160419ebc8f51814fb3271a"),
          },
          {
            from_hex("0b0b0aaf009c1c9c9a6103a004cab06cd0"),
            from_hex("0bbb0aaf003f0045b07615185317303eb9"),
            from_hex("0c0bbb0aaf00e638bf4dbafe35dc1853cc73"),
          },
          {
            from_hex("0b0baaaf002c21652122601e056a27bc1d"),
            from_hex("0bbbaaaf001a40ca810397ca646e2b08c3"),
            from_hex("0c0bbbaaaf00cbdcb9e4e401ee566e91e386"),
          },
        },
        {
          {
            from_hex("0b0b00a000dadd1533c0418d7ab42e193b"),
            from_hex("0bbb00a000144ac3cfd5e4a563b8766bad"),
            from_hex("0c0bbb00a000b753901426810fcdd91261a2"),
          },
          {
            from_hex("0b0b0aa00006be6cd4471e30285c6e51df"),
            from_hex("0bbb0aa0008cea2fb844ed64406dc495b6"),
            from_hex("0c0bbb0aa000ad1376f533ebf44a3f778c81"),
          },
          {
            from_hex("0b0baaa000a20b1f3ed8499f8a740a02a5"),
            from_hex("0bbbaaa0006f311c5a7aaf02895ea699ed"),
            from_hex("0c0bbbaaa000ede89b44263ee25013fc615d"),
          },
        },
      } } },
    { CipherSuite::AES_GCM_128_SHA256,
      { {
        {
          {
            from_hex("0b0b00a0006ecb201768cf6a0f14bbee09ad490c5a4e215650"),
            from_hex("0bbb00a000bc4944c23dd62883911c247c4d42fb9cd1a60883"),
            from_hex("0c0bbb00a000ea232bd73f103aebef947a487de72cbf4fae7add"),
          },
          {
            from_hex("0b0b0aa000d0ead9e0b2bb2e52f82c1e377c27a49115694cc5"),
            from_hex("0bbb0aa000fc894af5b173474384dc9b08d65875a85eeb42fa"),
            from_hex("0c0bbb0aa0005df598693c6f1e5d567869302ad52064aba28157"),
          },
          {
            from_hex("0b0baaa000051a97e25e94ab650b41890a0faa3747164ee2c0"),
            from_hex("0bbbaaa000be93b0c301782fc4b7abf0a66b36120138fc86b9"),
            from_hex("0c0bbbaaa0000e10273c8829af3eed30ad753763662e436a565d"),
          },
        },
        {
          {
            from_hex("0b0b00af0034f26ddfee46ec7844f3d99e2895f1ba4325c74d"),
            from_hex("0bbb00af00df339bf635ca2ae17d2f07b05e8edffd04518ae7"),
            from_hex("0c0bbb00af000f3f4f26bb98f7a57870e376ddddf0da8ad9c6ae"),
          },
          {
            from_hex("0b0b0aaf00d89a7e4ec825a3842f28c3ea40c8049f0cfe2084"),
            from_hex("0bbb0aaf002278d74c851303f0e57553dc3e1933c3459a8487"),
            from_hex("0c0bbb0aaf0076bccc828a1178dd36400b59a72d330e79e2bcc6"),
          },
          {
            from_hex("0b0baaaf001f07a6d0f61dc787b82ca0a13b38093910df4eff"),
            from_hex("0bbbaaaf00b69d6ada3cf060f7b010bb9b00fba19326e4d749"),
            from_hex("0c0bbbaaaf00fd3231ba3a9a5db1e87a01d5ce4cd74f742ae46c"),
          },
        },
        {
          {
            from_hex("0b0b00a000a054bb91c3097de21b58fea1fc1ccbc88570ebe5"),
            from_hex("0bbb00a000e1d4a1511cf16bb6c222672a91d26ab33505c356"),
            from_hex("0c0bbb00a0001865b9043654d287c8f3de32cc7cc6ad1bdfcfa9"),
          },
          {
            from_hex("0b0b0aa0005fad155349c32ddd6dca93ac6a60c0c9b9533eb8"),
            from_hex("0bbb0aa0003753e39c068bbfebe74ea6e2bb5234d90a5e7d6c"),
            from_hex("0c0bbb0aa000ae9ca700d753cafc556525a5348bb4ad4ece56b9"),
          },
          {
            from_hex("0b0baaa000e025c92b32b421efe6d6e1b9a04949498acaa9be"),
            from_hex("0bbbaaa000d079005f5e967a5408b29de179a69db552f41843"),
            from_hex("0c0bbbaaa000258742303cfbbcbf26ab10b490e866729242779b"),
          },
        },
      } } },
    { CipherSuite::AES_GCM_256_SHA512,
      { {
        {
          {
            from_hex("0b0b00a0008aa688a274acba1d92314a0f98794e1e50191392"),
            from_hex("0bbb00a0005437ed5f1545ce989de0eb38f02f1ed06c74bcbe"),
            from_hex("0c0bbb00a000439084e68b408b2430e9077739d9d0d53129188e"),
          },
          {
            from_hex("0b0b0aa000af72f544b51c937d217ab488ed44db7c18b5fe16"),
            from_hex("0bbb0aa00046c7750b1951594d8a12d76e4366b248d4422793"),
            from_hex("0c0bbb0aa0002c5825a674df250f82b7b51dd01583689664db7c"),
          },
          {
            from_hex("0b0baaa0008036596f12dcc552d0f03a794430d629439a205d"),
            from_hex("0bbbaaa0009237f7cb947e9aedb97b0bf69557604c2c3356f5"),
            from_hex("0c0bbbaaa000de9955378ee32a3aef148cd7ce05b93ee2508a74"),
          },
        },
        {
          {
            from_hex("0b0b00af001c3d824df4c26e2d76d65f40840491fb577e7d26"),
            from_hex("0bbb00af001e14b7f4ddc1b8fe5c29d279c7f35f46652b6265"),
            from_hex("0c0bbb00af00d638340784a28863256a470667cb8521dd682f2d"),
          },
          {
            from_hex("0b0b0aaf00f5ace84a9ac311216588637d012519d42461a698"),
            from_hex("0bbb0aaf006f2d1fc9a688382e5b85b01d9f49563a0aa80d29"),
            from_hex("0c0bbb0aaf00d8a865e3655d0a322106d35c3375ac3837a852c0"),
          },
          {
            from_hex("0b0baaaf00a9b54ca17d87a0f4a64260fdb374ff60331a06c4"),
            from_hex("0bbbaaaf00450e533cc76f31ffcd7080c2ec3d3e6ace9e9638"),
            from_hex("0c0bbbaaaf0048a8028b1a28719158ab19c6fd1a0bf2e532f26b"),
          },
        },
        {
          {
            from_hex("0b0b00a00015df4f7a226bd82e403c95eb0473c3b499b91c88"),
            from_hex("0bbb00a00052e7cd8bb8cb68fde112740b154fd7ac63dfe45d"),
            from_hex("0c0bbb00a00065539ae6be900e527bed4df63f9d5a28f0308659"),
          },
          {
            from_hex("0b0b0aa0003617ffb2846dff0d01f73cb768fe332fb25187da"),
            from_hex("0bbb0aa0006f6f9695211ec704a8374eea34768a29d28015b1"),
            from_hex("0c0bbb0aa000dd52ace0a6cec57446268a52e8b0ae9f88c541d6"),
          },
          {
            from_hex("0b0baaa000e37e4c8e7805ed3ec6d26f828825855c5f7b1be5"),
            from_hex("0bbbaaa00028b3993f0ff97d32547dc88b1479ab6f5e7626c6"),
            from_hex("0c0bbbaaa0001e93ae8c8daa541697b206ccff31ff12050ac035"),
          },
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
      ctx.add_epoch(epoch_ids[i], epoch_secrets[i], sender_bits);

      CHECK(tc.epochs[i].size() == sender_ids.size());
      for (size_t j = 0; j < tc.epochs[i].size(); j++) {

        CHECK(tc.epochs[i][j].size() == context_ids.size());
        for (size_t k = 0; k < tc.epochs[i][j].size(); k++) {
          auto encrypted = ctx.protect(
            epoch_ids[i], sender_ids[j], context_ids[k], ct_out, plaintext);
          CHECK(tc.epochs[i][j][k] == to_bytes(encrypted));

          auto decrypted = ctx.unprotect(pt_out, tc.epochs[i][j][k]);
          CHECK(plaintext == to_bytes(decrypted));
        }
      }
    }
  }
}

TEST_CASE("MLS Round-Trip with context")
{
  ensure_fips_if_required();

  const auto epoch_bits = 4;
  const auto test_epochs = 1 << (epoch_bits + 1);
  const auto epoch_rounds = 10;
  const auto plaintext = from_hex("00010203");
  const auto sender_id_a = MLSContext::SenderID(0xA0A0A0A0);
  const auto sender_id_b = MLSContext::SenderID(0xA1A1A1A1);
  const auto sender_id_bits = size_t(32);
  const auto context_id_0 = 0xB0B0;
  const auto context_id_1 = 0xB1B1;

  const std::vector<CipherSuite> suites{
    CipherSuite::AES_CM_128_HMAC_SHA256_4,
    CipherSuite::AES_CM_128_HMAC_SHA256_8,
    CipherSuite::AES_GCM_128_SHA256,
    CipherSuite::AES_GCM_256_SHA512,
  };

  auto pt_out = bytes(plaintext.size());
  auto ct_out_1 = bytes(plaintext.size() + max_overhead);
  auto ct_out_0 = bytes(plaintext.size() + max_overhead);

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
        auto encrypted_ab_0 = member_a_0.protect(
          epoch_id, sender_id_a, context_id_0, ct_out_0, plaintext);
        auto decrypted_ab_0 =
          to_bytes(member_b.unprotect(pt_out, encrypted_ab_0));
        CHECK(plaintext == decrypted_ab_0);

        auto encrypted_ab_1 = member_a_1.protect(
          epoch_id, sender_id_a, context_id_1, ct_out_1, plaintext);
        auto decrypted_ab_1 =
          to_bytes(member_b.unprotect(pt_out, encrypted_ab_1));
        CHECK(plaintext == decrypted_ab_1);

        std::cout << encrypted_ab_0 << " " << encrypted_ab_1 << std::endl;
        CHECK(to_bytes(encrypted_ab_0) != to_bytes(encrypted_ab_1));

        auto encrypted_ba =
          member_b.protect(epoch_id, sender_id_b, ct_out_0, plaintext);
        auto decrypted_ba_0 =
          to_bytes(member_a_0.unprotect(pt_out, encrypted_ba));
        auto decrypted_ba_1 =
          to_bytes(member_a_1.unprotect(pt_out, encrypted_ba));
        CHECK(plaintext == decrypted_ba_0);
        CHECK(plaintext == decrypted_ba_1);
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
#endif // 0
