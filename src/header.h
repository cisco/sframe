#pragma once

#include <sframe/sframe.h>

namespace sframe {

struct Header {
  const KeyID key_id;
  const Counter counter;

  size_t size() const;

  static std::tuple<Header, input_bytes> decode(input_bytes data);
  size_t encode(output_bytes buffer) const;

  static constexpr size_t min_size = 1;
  static constexpr size_t max_size = 1 + 7 + 7;
};

} // namespace sframe
