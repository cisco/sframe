#pragma once

#include <sframe/vector.h>

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
