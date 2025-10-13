#pragma once

#include <optional>
#include <utility>

namespace SFRAME_NAMESPACE {

// Error types to replace exceptions
enum class SFrameErrorType
{
  NONE = 0,
  INTERNAL_ERROR,
  INVALID_PARAMETER_ERROR,
};

class SFrameError
{
public:
  SFrameError() = default;

  explicit SFrameError(SFrameErrorType type)
    : type_(type)
  {
  }

  SFrameError(SFrameErrorType type, std::string message)
    : type_(type)
    , message_(message)
  {
  }

  SFrameErrorType type() const { return type_; }

  const char* message() const { return message_.c_str(); }

  bool ok() const { return type_ == SFrameErrorType::NONE; }

private:
  SFrameErrorType type_ = SFrameErrorType::NONE;
  std::string message_;
};

template<typename T>
class Result
{
  template<typename U>
  friend class Result;

public:
  typedef T element_type;

  explicit Result()
    : error_(SFrameErrorType::INTERNAL_ERROR)
  {
  }

  Result(SFrameError error)
    : error_(error)
  {
  }

  Result(const T& value)
    : value_(value)
  {
  }

  Result(T&& value)
    : value_(std::move(value))
  {
  }

  Result(const Result& other) = delete;
  Result& operator=(const Result& other) = delete;

  Result(Result&& other) noexcept
    : error_(std::move(other.error_))
    , value_(std::move(other.value_))
  {
  }

  Result& operator=(Result&& other) noexcept
  {
    error_ = std::move(other.error_);
    value_ = std::move(other.value_);
    return *this;
  }

  template<typename U>
  Result(Result<U> other)
    : error_(std::move(other.error_))
    , value_(std::move(other.value_))
  {
  }

  template<typename U>
  Result& operator=(Result<U> other)
  {
    error_ = std::move(other.error_);
    value_ = std::move(other.value_);
    return *this;
  }

  SFrameError error() const
  {
    return error_;
  }

  SFrameError MoveError()
  {
    return std::move(error_);
  }

  bool ok() const { return error_.ok(); }

  const T& value() const { return *value_; }

  T& value() { return *value_; }

  T MoveValue() { return std::move(*value_); }

private:
  SFrameError error_;
  std::optional<T> value_;
};

// Helper functions to create Results
template<typename T>
Result<T>
Ok(const T& value)
{
  return Result<T>(value);
}

template<typename T>
Result<T>
Ok(T&& value)
{
  return Result<T>(std::move(value));
}

template<typename T>
Result<T>
Err(SFrameErrorType error, const char* message = "")
{
  return Result<T>(SFrameError(error, message));
}

} // namespace SFRAME_NAMESPACE