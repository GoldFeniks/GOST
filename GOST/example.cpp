#include "cipher.hpp"
#include "reader.hpp"
#include "converter.hpp"
#include <iostream>
#include <string>

using namespace gost_magma;

void test_string() {
    static const std::string s = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nullam euismod tellus enim, eget elementum ipsum aliquet malesuada. Aliquam rhoncus ipsum at ante facilisis dictum. In tristique libero eu tortor tempus.";
    cipher cip;
    const auto bytes = cip.encrypt_ecb(to_bytes<std::string>(s));
    const auto rs = to_string(cip.decrypt_ecb(bytes));
    std::cout << rs << std::endl;
    system("pause");
}

int main(int argc, char* argv[]) {
    test_string();
}
