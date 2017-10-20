#include "cipher.hpp"
#include "converter.hpp"
#include <iostream>

int main() {
    GOST::Cipher cipher;
    std::string s = "I'm plain text!!! Do you hear me? I AM PLAIN TEXT!!! PLAIN!!!";
    auto bytes = GOST::toBytes(s);
    std::cout << "Text: " << s << std::endl;
    auto in = cipher.EncryptECB(bytes);
    std::cout << "ECB Encrypted: " << GOST::toString(in) << std::endl;
    auto out = cipher.DecryptECB(in);
    std::cout << "ECB Decrypted: " << GOST::toString(out) << std::endl;
    in = cipher.EncryptCBC(bytes, 0x0101010101010101);
    std::cout << "CBC Encrypted: " << GOST::toString(in) << std::endl;
    out = cipher.DecryptCBC(in, 0x0101010101010101);
    std::cout << "CBC Decrypted: " << GOST::toString(out) << std::endl;
    in = cipher.EncryptCFB(bytes, 0x1010101010101010);
    std::cout << "CFB Encrypted: " << GOST::toString(in) << std::endl;
    out = cipher.DecryptCFB(in, 0x1010101010101010);
    std::cout << "CFB Decrypted: " << GOST::toString(out) << std::endl;
    in = cipher.EncryptOFB(bytes, 0x0011001100110011);
    std::cout << "OFB Encrypted: " << GOST::toString(in) << std::endl;
    out = cipher.DecryptOFB(in, 0x0011001100110011);
    std::cout << "OFB Decrypted: " << GOST::toString(out) << std::endl;
    system("pause");
    return 0;
}