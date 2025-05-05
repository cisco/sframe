#pragma once

#ifdef NO_ALLOC

#include <sframe/vector.h>

namespace sframe {

template<typename K, typename V, size_t N>
class map : private vector<std::optional<std::pair<K, V>>, N>
{
public:
  template<class... Args>
  void emplace(Args&&... args)
  {
    const auto pos = std::find_if(
      this->begin(), this->end(), [&](const auto& pair) { return !pair; });
    if (pos == this->end()) {
      throw std::out_of_range("map out of space");
    }

    pos->emplace(args...);
  }

  auto find(const K& key)
  {
    return std::find_if(this->begin(), this->end(), [&](const auto& pair) {
      return pair && pair.value().first == key;
    });
  }

  auto find(const K& key) const
  {
    return std::find_if(this->begin(), this->end(), [&](const auto& pair) {
      return pair && pair.value().first == key;
    });
  }

  bool contains(const K& key) const { return find(key) != this->end(); }

  const V& at(const K& key) const
  {
    const auto pos = find(key);
    if (pos == this->end()) {
      throw std::out_of_range("map key not found");
    }

    return pos->value().second;
  }

  V& at(const K& key)
  {
    auto pos = find(key);
    if (pos == this->end()) {
      throw std::out_of_range("map key not found");
    }

    return pos->value().second;
  }

  template<typename F>
  void erase_if_key(F&& f)
  {
    const auto to_erase = [&f](const auto& maybe_pair) {
      return maybe_pair && f(maybe_pair.value().first);
    };

    std::replace_if(this->begin(), this->end(), to_erase, std::nullopt);
  }
};

} // namespace sframe

#else // ifdef NO_ALLOC

#include <map>

namespace sframe {

// NOTE: NOT RECOMMENDED FOR USE OUTSIDE THIS LIBRARY
//
// We have used public inheritance from std::map<T> to simplify the interface
// here.  This works fine for the use cases we have within this library.  If you
// choose to use this map type outside this library, you MUST NOT store it as a
// std::map<T> pointer or reference.  This will cause memory leaks, because the
// destructor ~std::map<T> is not virtual.
template<typename K, typename V, size_t N>
class map : public std::map<K, V>
{
private:
  using parent = std::map<K, V>;

public:
  bool contains(const K& key) const { return this->count(key) > 0; }

  template<typename F>
  void erase_if_key(F&& f)
  {
    for (auto iter = this->begin(); iter != this->end();) {
      if (f(iter->first)) {
        iter = this->erase(iter);
      } else {
        ++iter;
      }
    }
  }
};

} // namespace sframe

#endif // def NO_ALLOC
