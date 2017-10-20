#include "cipher.hpp"
#include "converter.hpp"
#include <iostream>

int main() {
    GOST::Cipher cipher(100, 100);
    auto in = cipher.EncryptOFB(GOST::toBytes("I'm plain text!!! Do you hear me? I AM PLAIN TEXT!!! PLAIN!!!"), 10);
    std::cout << GOST::toString(in) << std::endl;
    auto out = cipher.DecryptOFB(in, 10);
    std::cout << GOST::toString(out) << std::endl;
    system("pause");
    return 0;
}