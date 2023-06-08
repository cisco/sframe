#pragma once

#include <sframe/sframe.h>

namespace sframe {

// Exposed to sframe.cpp to aid in nonce formation
void
encode_uint(uint64_t val, output_bytes buffer);

} // namespace sframe
