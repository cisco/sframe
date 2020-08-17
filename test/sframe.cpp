#include <doctest/doctest.h>
#include <sframe/sframe.h>

#include <iostream>    // for string, operator<<
#include <map>         // for map
#include <stdexcept>   // for invalid_argument
#include <string>      // for basic_string, operator==

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
    case CipherSuite::AES_GCM_128:
      return "AES_GCM_128";

    case CipherSuite::AES_GCM_256:
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
    { CipherSuite::AES_GCM_128,
      {
        from_hex("101112131415161718191a1b1c1d1e1f"),
        from_hex("1700111266b003b9cd7225d9d4cb6e5c8143bb80bf98"),
        from_hex("1701c7845beffa61a9d13b2a85bd8e181e6e637aedcd"),
        from_hex("1702475146c7d0d0aac1c97cf2d5c7610bac15ba9515"),
        from_hex("1affff00111266b0a5fc4fc173aafd0c5c56956dc6bc87c7"),
        from_hex("2affff0100f15d230ba637848d89c9910dde14f9f23372e610"),
      } },
    { CipherSuite::AES_GCM_256,
      {
        from_hex("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c"
                 "3d3e3f"),
        from_hex("1700e32fe35a4af2c10a224d72d44f9bd0cb037cdb81"),
        from_hex("17010bea6abc8a7b049b74f09e9eaecb1c5d58291ccb"),
        from_hex("1702385144f2c67d0ee316f05ce00bb9ae10f83e0e24"),
        from_hex("1affff00e32fe35a8b7f2445746251610df8600801b02829"),
        from_hex("2affff01008e9c505cb18ec35ea0bdbaa8727f50921a52e902"),
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
