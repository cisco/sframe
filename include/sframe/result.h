#pragma once

#include <utility>
#include <variant>
#include <string>
#include <optional>

#include <namespace.h>

namespace SFRAME_NAMESPACE {

// Error types to replace exceptions
enum class SFrameErrorType
{
  internal_error = 1,
  invalid_parameter_error,
  buffer_too_small_error,
  crypto_error,
  unsupported_ciphersuite_error,
  authentication_error,
  invalid_key_usage_error,
};

class SFrameError
{
public:
  SFrameError() = default;

  explicit SFrameError(SFrameErrorType type)
    : type_(type)
    , message_(nullptr)
  {
  }

  SFrameError(SFrameErrorType type, const char* message)
    : type_(type)
    , message_(message)
  {
  }

  SFrameError(const SFrameError& other) = default;
  SFrameError(SFrameError&& other) noexcept = default;
  SFrameError& operator=(SFrameError&& other) noexcept = default;

  SFrameErrorType type() const { return type_; }

  const char* message() const { return message_; }

private:
  SFrameErrorType type_;
  const char* message_ = nullptr;
};

// Helper to convert SFrameError to appropriate exception type
void
throw_on_error(const SFrameError& error);

template<typename T>
class Result
{
public:
  typedef T element_type;

  static Result ok(const T& value) { return Result<T>(value); }

  static Result ok(T&& value) { return Result<T>(std::move(value)); }

  static Result err(SFrameErrorType error, const char* message = nullptr)
  {
    return Result<T>(SFrameError(error, message));
  }

  static Result err(SFrameError&& error)
  {
    return Result<T>(std::move(error));
  }

  Result(SFrameError error)
    : data_(std::move(error))
  {
  }

  Result(const T& value)
    : data_(value)
  {
  }

  Result(T&& value)
    : data_(std::move(value))
  {
  }

  Result(const Result& other) = delete;
  Result& operator=(const Result& other) = delete;

  Result(Result&& other) noexcept
    : data_(std::move(other.data_))
  {
  }

  Result& operator=(Result&& other) noexcept
  {
    data_ = std::move(other.data_);
    return *this;
  }

  template<typename U>
  Result(Result<U>&& other)
    : data_(std::move(other.data_))
  {
  }

  template<typename U>
  Result& operator=(Result<U>&& other)
  {
    data_ = std::move(other.data_);
    return *this;
  }

  T value() { return std::move(std::get<T>(data_)); }

  SFrameError error()
  {
    if (std::holds_alternative<SFrameError>(data_)) {
      auto error = std::get<SFrameError>(data_);
      return error;
    }
    return SFrameError(); // Default OK error
  }

  bool is_ok() const { return std::holds_alternative<T>(data_); }

  bool is_err() const { return std::holds_alternative<SFrameError>(data_); }

private:
  std::variant<T, SFrameError> data_;
};

// Specialization for Result<void>
template<>
class Result<void>
{
public:
  typedef void element_type;

  static Result ok() { return Result<void>(); }

  static Result err(SFrameErrorType error,
                          const char* message = nullptr)
  {
    return Result<void>(SFrameError(error, message));
  }

  static Result err(SFrameError&& error)
  {
    return Result<void>(std::move(error));
  }

  Result()  = default;
  Result(SFrameError error)
    : error_(std::move(error))
  {
  }
  Result(const Result& other) = delete;
  Result& operator=(const Result& other) = delete;
  Result(Result&& other) noexcept = default;
  Result& operator=(Result&& other) noexcept = default;

  void value() { /* void has no value to move */ }

  SFrameError error() { return error_.value(); }

  bool is_ok() const { return !error_.has_value(); }
  
  bool is_err() const { return error_.has_value(); }

private:
  std::optional<SFrameError> error_;
};

} // namespace SFRAME_NAMESPACE