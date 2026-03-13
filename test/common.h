#include <namespace.h>
#include <sframe/result.h>
#include <sframe/sframe.h>

#include <string>
#include <vector>

// Unwrap a Result<T> value in a test context.
// Throws std::runtime_error on error so doctest can catch and report it.
#define UNWRAP(expr)                                                            \
  [&]() {                                                                      \
    auto _sframe_unwrap = (expr);                                              \
    if (_sframe_unwrap.is_err()) {                                             \
      const auto* _msg = _sframe_unwrap.error().message();                    \
      throw std::runtime_error(_msg ? _msg : "UNWRAP: Result error");          \
    }                                                                          \
    return _sframe_unwrap.value();                                             \
  }()

using bytes = std::vector<uint8_t>;

bytes
from_hex(const std::string& hex);
std::string
to_hex(const SFRAME_NAMESPACE::input_bytes data);

template<typename T>
bytes
to_bytes(const T& range)
{
  return bytes(range.begin(), range.end());
}
