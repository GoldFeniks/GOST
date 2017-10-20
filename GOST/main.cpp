#include "cipher.hpp"
#include "converter.hpp"
#include <iostream>

int main() {
    GOST::Cipher cipher(100, 100);
    auto in = cipher.EncryptECB(GOST::toBytes("I'm textI'm text"));
    auto out = cipher.DecryptECB(in);
    std::cout << GOST::toString(out) << std::endl;
    system("pause");
    return 0;
}