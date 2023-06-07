#include "header.h"

namespace sframe {

static size_t
uint_size(uint64_t val)
{
  for (unsigned int i = 0; i < 8; i += 1) {
    if ((val >> (8 * i)) == 0) {
      return i;
    }
  }

  return 8;
}

void
encode_uint(uint64_t val, output_bytes buffer)
{
  size_t size = buffer.size();
  for (size_t i = 0; i < size && i < 8; i++) {
    buffer[size - i - 1] = uint8_t(val >> (8 * i));
  }
}

static uint64_t
decode_uint(input_bytes data)
{
  uint64_t val = 0;
  for (size_t i = 0; i < data.size(); i++) {
    val = (val << 8) + static_cast<uint64_t>(data[i]);
  }
  return val;
}

static size_t
kid_size(KeyID key_id) {
  if (key_id < 0x08) {
    return 0;
  } else {
    return uint_size(key_id);
  }
}

static size_t
ctr_size(Counter counter) {
  const auto ctr_size = uint_size(counter);
  if (ctr_size == 0) {
    // CTR always takes at least one byte
    return 1;
  }

  return ctr_size;
}

Header::Header(KeyID key_id_in, Counter counter_in)
  : key_id(key_id_in)
  , counter(counter_in)
  , key_id_size(kid_size(key_id))
  , counter_size(ctr_size(counter))
{
  auto buffer_out = output_bytes(buffer);
  buffer_out[0] = uint8_t((counter_size - 1) << 4);
  if (key_id < 0x08) {
    buffer_out[0] |= static_cast<uint8_t>(key_id);
  } else {
    buffer_out[0] |= static_cast<uint8_t>(0x08 | key_id_size);
    encode_uint(key_id, buffer_out.subspan(1, key_id_size));
  }

  encode_uint(counter, buffer_out.subspan(1 + key_id_size, counter_size));
}

Header
Header::parse(input_bytes buffer)
{
  if (buffer.size() < min_size) {
    throw buffer_too_small_error("Ciphertext too small to decode header");
  }

  auto cfg = buffer[0];
  auto ctr_size = size_t((cfg >> 4) & 0x07) + 1;
  auto kid_long = (cfg & 0x08) > 0;
  auto kid_size = size_t(cfg & 0x07);

  auto key_id = KeyID(kid_size);
  if (kid_long) {
    if (buffer.size() < 1 + kid_size) {
      throw buffer_too_small_error("Ciphertext too small to decode KID");
    }

    key_id = KeyID(decode_uint(buffer.subspan(1, kid_size)));
  } else {
    kid_size = 0;
  }

  auto total_size = 1 + ctr_size + kid_size;

  if (buffer.size() < 1 + kid_size + ctr_size) {
    throw buffer_too_small_error("Ciphertext too small to decode CTR");
  }
  auto counter = Counter(decode_uint(buffer.subspan(1 + kid_size, ctr_size)));

  return Header(key_id, counter, buffer.subspan(0, total_size));
}

Header::Header(KeyID key_id_in, Counter counter_in, input_bytes encoded)
  : key_id(key_id_in)
  , counter(counter_in)
  , key_id_size(kid_size(key_id))
  , counter_size(ctr_size(counter))
{
  std::copy(encoded.begin(), encoded.end(), buffer.begin());
}

input_bytes
Header::encoded() const
{
  return input_bytes(buffer).subspan(0, size());
}

size_t
Header::size() const
{
  return 1 + key_id_size + counter_size;
}

} // namespace sframe
