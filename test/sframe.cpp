#include <doctest/doctest.h>
#include <sframe/sframe.h>

#include <iostream>  // for string, operator<<
#include <map>       // for map
#include <stdexcept> // for invalid_argument
#include <string>    // for basic_string, operator==

using namespace sframe;

bytes
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

std::string
ciphersuite_name(CipherSuite suite)
{
  switch (suite) {
    case CipherSuite::AES_GCM_128_SHA256:
      return "AES_GCM_128";

    case CipherSuite::AES_GCM_256_SHA512:
      return "AES_GCM_256";

    default:
      return "Unknown ciphersuite";
  }
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
    { CipherSuite::AES_GCM_128_SHA256,
      {
        from_hex("101112131415161718191a1b1c1d1e1f"),
        from_hex("170003fcfa7edc96c2588a057f97da438fd964805f2e"),
        from_hex("17014999d3b99fc9f0aaf67bdaafbe2e063f62670e83"),
        from_hex("1702ba35e14d380bb8783ac7ce0df0956b87e59ccfa5"),
        from_hex("1affff0003fcfa7e05ae25c2e08687b08e6aa1b9e62eaf7e"),
        from_hex("2affff0100ab7fed4b60f2a2bce541613a50fafc5adb518287"),
      } },
    { CipherSuite::AES_GCM_256_SHA512,
      {
        from_hex(
          "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
        from_hex("1700eb166e453dac4de40e2bc7a2f07aaea11bbbb36c"),
        from_hex("1701a817dcfd4e8aa98981459086566f3cd30701af9c"),
        from_hex("1702294c87f5af03eb0602aed3a4beb2104ecc11653e"),
        from_hex("1affff00eb166e45641c5c46e602d8f429d2a0de241d007a"),
        from_hex("2affff010069f14831479e0ebe67276c36006aa5d1c584f817"),
      } },
  };

  for (auto& pair : cases) {
    auto& suite = pair.first;
    auto& tc = pair.second;

    auto ctx = Context(suite);
    ctx.add_key(short_kid, tc.key);
    ctx.add_key(long_kid, tc.key);

    // KID=0x07, CTR=0, 1, 2
    auto ct0 = ctx.protect(short_kid, plaintext);
    auto ct1 = ctx.protect(short_kid, plaintext);
    auto ct2 = ctx.protect(short_kid, plaintext);

    CHECK(ct0 == tc.short_kid_ctr0);
    CHECK(ct1 == tc.short_kid_ctr1);
    CHECK(ct2 == tc.short_kid_ctr2);

    CHECK(plaintext == ctx.unprotect(ct0));
    CHECK(plaintext == ctx.unprotect(ct1));
    CHECK(plaintext == ctx.unprotect(ct2));

    // KID=0xffff, CTR=0
    auto ctLS = ctx.protect(long_kid, plaintext);
    for (Counter ctr = 1; ctr < long_ctr; ctr++) {
      ctx.protect(long_kid, plaintext);
    }
    auto ctLL = ctx.protect(long_kid, plaintext);

    CHECK(ctLS == tc.long_kid_short_ctr);
    CHECK(ctLL == tc.long_kid_long_ctr);

    CHECK(plaintext == ctx.unprotect(ct0));
    CHECK(plaintext == ctx.unprotect(ct1));
    CHECK(plaintext == ctx.unprotect(ct2));
  }
}

TEST_CASE("SFrame Round-Trip")
{
  const auto rounds = 1 << 9;
  const auto kid = KeyID(0x42);
  const auto plaintext = from_hex("00010203");
  const std::map<CipherSuite, bytes> keys{
    { CipherSuite::AES_GCM_128_SHA256,
      from_hex("101112131415161718191a1b1c1d1e1f") },
    { CipherSuite::AES_GCM_256_SHA512,
      from_hex("202122232425262728292a2b2c2d2e2f"
               "303132333435363738393a3b3c3d3e3f") },
  };

  for (auto& pair : keys) {
    auto& suite = pair.first;
    auto& key = pair.second;

    auto send = Context(suite);
    send.add_key(kid, key);

    auto recv = Context(suite);
    recv.add_key(kid, key);

    for (int i = 0; i < rounds; i++) {
      auto encrypted = send.protect(kid, plaintext);
      auto decrypted = recv.unprotect(encrypted);
      CHECK(decrypted == plaintext);
    }
  }
}
