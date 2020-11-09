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

size_t
Header::size() const
{
  auto kid_size = size_t(0);
  if (key_id > 0x07) {
    kid_size = uint_size(key_id);
  }

  const auto ctr_size = uint_size(counter);
  if ((kid_size > 0x07) || (ctr_size > 0x07)) {
    throw std::runtime_error("Header overflow");
  }

  return 1 + kid_size + ctr_size;
}

std::tuple<Header, input_bytes>
Header::decode(input_bytes buffer)
{
  if (buffer.size() < Header::min_size) {
    throw std::runtime_error("Ciphertext too small to decode header");
  }

  auto cfg = buffer[0];
  auto ctr_size = size_t((cfg >> 4) & 0x07);
  auto kid_long = (cfg & 0x08) > 0;
  auto kid_size = size_t(cfg & 0x07);

  auto key_id = KeyID(kid_size);
  if (kid_long) {
    if (buffer.size() < 1 + kid_size) {
      throw std::runtime_error("Ciphertext too small to decode KID");
    }

    key_id = KeyID(decode_uint(buffer.subspan(1, kid_size)));
  } else {
    kid_size = 0;
  }

  if (buffer.size() < 1 + kid_size + ctr_size) {
    throw std::runtime_error("Ciphertext too small to decode CTR");
  }
  auto counter = Counter(decode_uint(buffer.subspan(1 + kid_size, ctr_size)));

  return std::make_tuple(Header{ key_id, counter },
                         buffer.subspan(0, 1 + kid_size + ctr_size));
}

size_t
Header::encode(output_bytes buffer) const
{
  if (buffer.size() < size()) {
    throw std::runtime_error("Buffer too small to encode header");
  }

  auto kid_size = uint_size(key_id);
  if (key_id <= 0x07) {
    kid_size = 0;
    buffer[0] = static_cast<uint8_t>(key_id);
  } else {
    encode_uint(key_id, buffer.subspan(1, kid_size));
    buffer[0] = static_cast<uint8_t>(0x08 | kid_size);
  }

  auto ctr_size = uint_size(counter);
  if (ctr_size == 0) {
    // Counter always takes at least one byte
    ctr_size = 1;
  }

  encode_uint(counter, buffer.subspan(1 + kid_size, ctr_size));
  buffer[0] |= uint8_t(ctr_size << 4);

  return 1 + kid_size + ctr_size;
}

} // namespace sframe
