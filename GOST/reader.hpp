#pragma once
#include "cipher.hpp"
#include <functional>

namespace gost_magma {

    /**
     * \brief read all bytes from source of type T
     * \tparam T type of source
     * \param source source of bytes
     * \return read bytes
     */
    template<typename T>
    cipher::bytes_t read_bytes(T& source) {
        cipher::bytes_t result;
        while (!source.eof())
            result.push_back(source.get());
        return result;
    }

    /**
     * \brief read bytes from input stream
     * \param a stream to read bytes from
     */
    std::function<cipher::bytes_t(std::istream&)> read_bytes_stream = read_bytes<std::istream>;

    /**
     * \brief read num bytes from source of type T
     * \tparam T type of source
     * \tparam N type of num
     * \param source source of bytes
     * \param num number of bytes to be read
     * \return read bytes
     */
    template<typename T, typename N>
    cipher::bytes_t read_bytes_n(T& source, N num) {
        cipher::bytes_t result(num);
        N i = 0;
        while (!source.eof() && i < num)
            result[i++] = source.get();
        return result;
    }

    /**
     * \brief read b bytes from input stream
     * \tparam N type of b
     * \param a stream to read bytes from
     * \param b number of bytes to be read
     */
    template<typename N>
    std::function<cipher::bytes_t(std::istream&)> read_bytes_stream_n = read_bytes_n<std::istream, N>;
    
}// namespace gost_magma
