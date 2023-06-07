#pragma once

#include <sframe/sframe.h>

namespace sframe {

void
encode_uint(uint64_t val, output_bytes buffer);

struct Header
{
  const KeyID key_id;
  const Counter counter;

  Header(KeyID key_id_in, Counter counter_in);
  static Header parse(input_bytes buffer);

  input_bytes encoded() const;
  size_t size() const;

private:
  static constexpr size_t min_size = 1;
  static constexpr size_t max_size = 1 + 7 + 7;

  const size_t key_id_size;
  const size_t counter_size;
  std::array<uint8_t, max_size> buffer;

  Header(KeyID key_id_in, Counter counter_in, input_bytes encoded);
};

} // namespace sframe
