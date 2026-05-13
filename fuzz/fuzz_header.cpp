#include <cstddef>
#include <cstdint>

#include <header.h>

using namespace SFRAME_NAMESPACE;

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  auto input = input_bytes(data, size);
  (void)Header::parse(input);
  return 0;
}
