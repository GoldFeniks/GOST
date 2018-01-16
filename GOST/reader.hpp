#pragma once
#include "cipher.hpp"
#include <functional>

namespace gost_magma {

    template<typename T>
    cipher::bytes_t read_bytes(T& source) {
        cipher::bytes_t result;
        while (!source.eof())
            result.push_back(source.get());
        return result;
    }

    std::function<cipher::bytes_t(std::istream&)> read_bytes_stream = read_bytes<std::istream>;

    template<typename T, typename N>
    cipher::bytes_t read_bytes_n(T& source, N num) {
        cipher::bytes_t result(num);
        N i = 0;
        while (!source.eof() && i < num)
            result[i++] = source.get();
        return result;
    }

    template<typename N>
    std::function<cipher::bytes_t(std::istream&)> read_bytes_stream_n = read_bytes_n<std::istream, N>;
    
}// namespace gost_magma
