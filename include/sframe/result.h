#pragma once

#include <utility>
#include <variant>

namespace SFRAME_NAMESPACE {

// Error types to replace exceptions
enum class SFrameErrorType
{
  none = 0,
  internal_error,
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
  SFrameError()
    : type_(SFrameErrorType::none)
    , message_()
  {
  }

  explicit SFrameError(SFrameErrorType type)
    : type_(type)
    , message_()
  {
  }

  SFrameError(SFrameErrorType type, std::string message)
    : type_(type)
    , message_(std::move(message))
  {
  }

  // Copy constructor
  SFrameError(const SFrameError& other)
    : type_(SFrameErrorType::none)
    , message_(other.message_)
  {
    type_ = other.type_;
  }
  
  // Copy assignment
  SFrameError& operator=(const SFrameError& other)
  {
    if (this != &other) {
      type_ = other.type_;
      message_ = other.message_;
    }
    return *this;
  }

  // Move constructor
  SFrameError(SFrameError&& other) noexcept
    : type_(other.type_)
    , message_(std::move(other.message_))
  {
  }
  
  // Move assignment
  SFrameError& operator=(SFrameError&& other) noexcept
  {
    if (this != &other) {
      type_ = other.type_;
      message_ = std::move(other.message_);
    }
    return *this;
  }

  SFrameErrorType type() const { return type_; }

  const char* message() const { return message_.c_str(); }

  bool ok() const { return type_ == SFrameErrorType::none; }

private:
  SFrameErrorType type_ = SFrameErrorType::none;
  std::string message_;
};

template<typename T>
class Result
{
public:
  typedef T element_type;

  static Result<T> ok(const T& value) { return Result<T>(value); }

  static Result<T> ok(T&& value) { return Result<T>(std::move(value)); }

  static Result<T> err(SFrameErrorType error, const std::string& message = "")
  {
    return Result<T>(SFrameError(error, message));
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

  SFrameError error() const
  {
    if (std::holds_alternative<SFrameError>(data_)) {
      return std::get<SFrameError>(data_);
    }
    return SFrameError(); // Default OK error
  }

  SFrameError MoveError()
  {
    if (std::holds_alternative<SFrameError>(data_)) {
      auto error = std::get<SFrameError>(data_);
      return error;
    }
    return SFrameError(); // Default OK error
  }

  bool is_ok() const { return std::holds_alternative<T>(data_); }

  bool is_err() const { return std::holds_alternative<SFrameError>(data_); }

  const T& value() const { return std::get<T>(data_); }

  T& value() { return std::get<T>(data_); }

  T MoveValue() { return std::move(std::get<T>(data_)); }

private:
  std::variant<T, SFrameError> data_;
};

} // namespace SFRAME_NAMESPACE