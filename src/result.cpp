#include <sframe/result.h>
#include <sframe/sframe.h>

namespace SFRAME_NAMESPACE {

void
throw_on_error(const SFrameError& error)
{
  switch (error.type()) {
    case SFrameErrorType::none:
      return;
    case SFrameErrorType::buffer_too_small_error:
      throw buffer_too_small_error(error.message());
    case SFrameErrorType::invalid_parameter_error:
      throw invalid_parameter_error(error.message());
    case SFrameErrorType::crypto_error:
      throw crypto_error();
    case SFrameErrorType::unsupported_ciphersuite_error:
      throw unsupported_ciphersuite_error();
    case SFrameErrorType::authentication_error:
      throw authentication_error();
    case SFrameErrorType::invalid_key_usage_error:
      throw invalid_key_usage_error(error.message());
    default:
      throw std::runtime_error(error.message());
  }
}

} // namespace SFRAME_NAMESPACE
