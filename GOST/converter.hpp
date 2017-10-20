#pragma once
#include <vector>
#include <string>

namespace GOST {

    std::vector<unsigned char> toBytes(const std::string& string);
    std::string toString(const std::vector<unsigned char>& bytes);

}// namespace GOST
