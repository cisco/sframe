#pragma once

#include <gsl/gsl-lite.hpp>

#ifdef NO_ALLOC

namespace sframe {

template<typename T, size_t N>
class vector
{
private:
  std::array<T, N> _data;
  size_t _size;

public:
  constexpr vector()
    : _size(N)
  {
    std::fill(_data.begin(), _data.end(), T());
  }

  constexpr vector(size_t size)
  {
    std::fill(_data.begin(), _data.end(), T());
    resize(size);
  }

  constexpr vector(std::initializer_list<uint8_t> content)
  {
    resize(content.size());
    std::copy(content.begin(), content.end(), _data.begin());
  }

  constexpr vector(gsl::span<const T> content)
  {
    resize(content.size());
    std::copy(content.begin(), content.end(), _data.begin());
  }

  // XXX(RLB) This constructor seems redundant with the prior one, but for some
  // reason the compiler won't auto-convert from vector to span.
  template<size_t M>
  constexpr vector(const vector<T, M>& content)
  {
    resize(content.size());
    std::copy(content.begin(), content.end(), _data.begin());
  }

  uint8_t* data() { return _data.data(); }

  auto begin() const { return _data.begin(); }
  auto begin() { return _data.begin(); }

  auto end() const { return _data.begin() + _size; }
  auto end() { return _data.begin() + _size; }

  auto size() const { return _size; }
  auto capacity() const { return N; }
  void resize(size_t size)
  {
    if (size > N) {
      throw std::out_of_range("vector out of space");
    }

    _size = size;
  }

  void push(T&& item)
  {
    resize(_size + 1);
    _data.at(_size - 1) = item;
  }

  void append(gsl::span<const T> content)
  {
    const auto start = _size;
    resize(_size + content.size());
    std::copy(content.begin(), content.end(), begin() + start);
  }

  auto& operator[](size_t i) { return _data.at(i); }
  const auto& operator[](size_t i) const { return _data.at(i); }

  operator gsl::span<const T>() const { return gsl::span(_data).first(_size); }
  operator gsl::span<T>() { return gsl::span(_data).first(_size); }
};

} // namespace sframe

#else // ifdef NO_ALLOC

#include <vector>

namespace sframe {

// NOTE: NOT RECOMMENDED FOR USE OUTSIDE THIS LIBRARY
//
// We have used public inheritance from std::vector<T> to simplify the interface
// here.  This works fine for the use cases we have within this library.  If you
// choose to use this vector type outside this library, you MUST NOT store it as
// a std::vector<T> pointer or reference.  This will cause memory leaks, because
// the destructor ~std::vector<T> is not virtual.
template<typename T, size_t N>
class vector : public std::vector<T>
{
private:
  using parent = std::vector<T>;

public:
  constexpr vector()
    : parent(N)
  {
  }

  constexpr vector(size_t size)
    : parent(size)
  {
  }

  constexpr vector(gsl::span<const T> content)
    : parent(content.begin(), content.end())
  {
  }

  template<size_t M>
  constexpr vector(const vector<T, M>& content)
    : parent(content)
  {
  }

  void append(gsl::span<const T> content)
  {
    const auto start = this->size();
    this->resize(start + content.size());
    std::copy(content.begin(), content.end(), this->begin() + start);
  }
};

} // namespace sframe

#endif // def NO_ALLOC
