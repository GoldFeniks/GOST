#include "cipher.hpp"
#include "converter.hpp"
#include <iostream>

int main() {
    GOST::Cipher cipher(100, 100);
    auto in = cipher.EncryptCBC(GOST::toBytes("I'm textI'm text"), 10);
    auto out = cipher.DecryptCBC(in, 10);
    std::cout << GOST::toString(out) << std::endl;
    system("pause");
    return 0;
}