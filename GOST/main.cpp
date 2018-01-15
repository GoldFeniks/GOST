#define _CRT_SECURE_NO_WARNINGS
#include "cipher.hpp"
#include "converter.hpp"
#include "reader.hpp"
#include <iostream>
#include <fstream>

void out_file(const std::vector<unsigned char> bytes, const std::string file) {
    std::ofstream out(file, std::ios::binary);
    for (auto i : bytes)
        out << i;
}

void test_file(const std::string name) {
    gost_magma::cipher cipher;
    const auto bytes = gost_magma::read_bytes(std::ifstream(name, std::ios::binary));
    auto in = cipher.encrypt_ecb(bytes);   
    out_file(in, std::string("ECB") + name + std::string(".in"));
    auto out = cipher.decrypt_ecb(in);
    out_file(out, std::string("ECB") + name + std::string(".out"));
    in = cipher.encrypt_cbc(bytes, 0x0101010101010101);
    out_file(in, std::string("CBC") + name + std::string(".in"));
    out = cipher.decrypt_cbc(in, 0x0101010101010101);
    out_file(out, std::string("CBC") + name + std::string(".out"));
    in = cipher.encrypt_cfb(bytes, 0x1010101010101010);
    out_file(in, std::string("CFB") + name + std::string(".in"));
    out = cipher.decrypt_cfb(in, 0x1010101010101010);
    out_file(out, std::string("CFB") + name + std::string(".out"));
    in = cipher.encrypt_ofb(bytes, 0x0011001100110011);
    out_file(in, std::string("OFB") + name + std::string(".in"));
    out = cipher.decrypt_ofb(in, 0x0011001100110011);
    out_file(out, std::string("OFB") + name + std::string(".out"));
}

void test()  {
    gost_magma::cipher cipher;
    std::string s = "I'm plain text!!! Do you hear me? I AM PLAIN TEXT!!! PLAIN!!!";
    const auto bytes = gost_magma::to_bytes<std::string>(s);
    std::cout << "Text: " << s << std::endl;
    auto in = cipher.encrypt_ecb(bytes);
    std::cout << "ECB Encrypted: " << gost_magma::to_string(in) << std::endl;
    auto out = cipher.decrypt_ecb(in);
    std::cout << "ECB Decrypted: " << gost_magma::to_string(out) << std::endl;
    in = cipher.encrypt_cbc(bytes, 0x0101010101010101);
    std::cout << "CBC Encrypted: " << gost_magma::to_string(in) << std::endl;
    out = cipher.decrypt_cbc(in, 0x0101010101010101);
    std::cout << "CBC Decrypted: " << gost_magma::to_string(out) << std::endl;
    in = cipher.encrypt_cfb(bytes, 0x1010101010101010);
    std::cout << "CFB Encrypted: " << gost_magma::to_string(in) << std::endl;
    out = cipher.decrypt_cfb(in, 0x1010101010101010);
    std::cout << "CFB Decrypted: " << gost_magma::to_string(out) << std::endl;
    in = cipher.encrypt_ofb(bytes, 0x0011001100110011);
    std::cout << "OFB Encrypted: " << gost_magma::to_string(in) << std::endl;
    out = cipher.decrypt_ofb(in, 0x0011001100110011);
    std::cout << "OFB Decrypted: " << gost_magma::to_string(out) << std::endl;
    system("pause");
}

int main() {
    const  auto t = time(nullptr);
    //test();
    test_file("1.exe");
    std::cout << time(nullptr) - t << std::endl;
    system("pause");
    return 0;
}