#pragma once
#include <vector>
#include <string>
#include <functional>
#include "cipher.hpp"

namespace gost_magma {

    template<typename F, typename T>
    T convert(const F& from) {
        return T(from.begin(), from.end());
    }

    template<typename T>
    using to_bytes = convert<T, cipher::bytes_t>;

    std::function<std::string(cipher::bytes_t)> to_string = convert<cipher::bytes_t, std::string>;

}// namespace gost_magma
