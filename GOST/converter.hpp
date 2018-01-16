#pragma once
#include <vector>
#include <string>
#include <functional>
#include "cipher.hpp"

namespace gost_magma {

    /**
     * \brief converts array-like value of type F into array-like value of type T
     * \tparam F type of value to be converted
     * \tparam T type of result
     * \param from value to be converted
     * \return converted value
     */
    template<typename F, typename T>
    T convert(const F& from) {
        return T(from.begin(), from.end());
    }

    /**
     * \brief converts array-like value of type T into cipher::bytes_t
     * \tparam T type of value to be converted
     * \param 1 value to be converted
     */
    template<typename T>
    std::function<cipher::bytes_t(T)> to_bytes = convert<T, cipher::bytes_t>;

    /**
     * \brief converts cipher::bytes_t into std::string
     * \param 1 bytes to be converted
     */
    std::function<std::string(cipher::bytes_t)> to_string = convert<cipher::bytes_t, std::string>;

}// namespace gost_magma
