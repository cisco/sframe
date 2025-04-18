#pragma once

#include <sframe/sframe.h>

namespace sframe {

void
encode_uint(uint64_t val, output_bytes buffer);

struct Header
{
  const KeyID key_id;
  const Counter counter;

  size_t size() const;

  static std::tuple<Header, input_bytes> decode(input_bytes data);
  size_t encode(output_bytes buffer) const;

  static constexpr size_t min_size = 1;
  static constexpr size_t max_size = 1 + 8 + 8;
};

} // namespace sframe
