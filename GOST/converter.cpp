#include "converter.hpp"

std::vector<unsigned char> GOST::toBytes(const std::string& string) {
    return std::vector<unsigned char>(string.begin(), string.end());
}

std::string GOST::toString(const std::vector<unsigned char>& bytes) {
    return std::string(bytes.begin(), bytes.end());
}
