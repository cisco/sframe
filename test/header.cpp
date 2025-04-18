#include <doctest/doctest.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <sframe/sframe.h>

#include <iostream>
#include <map>       // for map
#include <stdexcept> // for invalid_argument
#include <string>    // for basic_string, operator==

using namespace sframe;

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

TEST_CASE("Header Known-Answer")
{
  struct KnownAnswerTest
  {
    uint64_t key_id;
    uint64_t counter;
    bytes encoding;
  };

  const auto cases = std::vector<KnownAnswerTest>{
    { 0, 0, from_hex("00") },
    { 0, 7, from_hex("07") },
    { 7, 0, from_hex("70") },
    { 7, 7, from_hex("77") },
    { 0, 8, from_hex("0808") },
    { 8, 0, from_hex("8008") },
    { 8, 8, from_hex("880808") },
    { 0xffffffffffffffff, 0, from_hex("f0ffffffffffffffff") },
    { 0, 0xffffffffffffffff, from_hex("0fffffffffffffffff") },
    { 0xffffffffffffffff,
      0xffffffffffffffff,
      from_hex("ffffffffffffffffffffffffffffffffff") },
  };

  for (const auto& tc : cases) {
    // Decode
    const auto decoded = Header::parse(tc.encoding);
    REQUIRE(decoded.key_id == tc.key_id);
    REQUIRE(decoded.counter == tc.counter);
    REQUIRE(decoded.size == tc.encoding.size());

    // Encode
    const auto to_encode = Header{ tc.key_id, tc.counter };
    const auto encoded = to_bytes(to_encode.encoded());
    REQUIRE(encoded == tc.encoding);
  }
}
