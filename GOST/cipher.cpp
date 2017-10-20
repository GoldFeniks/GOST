#include "cipher.hpp"
#include <random>
#include <cmath>

GOST::Cipher::bytes_t GOST::Cipher::EncryptECB(const bytes_t& message) {
    split_t ms = splitMessage(message);
    bytes_t result;
    for (auto it : ms) {
        auto bytes = toBytes(encrypt(it));
        result.insert(result.end(), bytes.begin(), bytes.end());
    }
    return result;
}

GOST::Cipher::bytes_t GOST::Cipher::DecryptECB(const bytes_t& message) {
    split_t ms = splitMessage(message);
    bytes_t result;
    for (auto it : ms) {
        auto bytes = toBytes(decrypt(it));
        result.insert(result.end(), bytes.begin(), bytes.end());
    }
    return result;
}

GOST::Cipher::bytes_t GOST::Cipher::EncryptCBC(const bytes_t& message, uint64_t IV) {
    split_t ms = splitMessage(message);
    bytes_t result;
    for (auto it : ms) {
        IV = encrypt(it ^ IV);
        auto bytes = toBytes(IV);
        result.insert(result.end(), bytes.begin(), bytes.end());
    }
    return result;
}

GOST::Cipher::bytes_t GOST::Cipher::DecryptCBC(const bytes_t& message, uint64_t IV) {
    split_t ms = splitMessage(message);
    bytes_t result;
    for (auto it : ms) {
        uint64_t t = decrypt(it);
        auto bytes = toBytes(t ^ IV);
        result.insert(result.end(), bytes.begin(), bytes.end());
        IV = it;
    }
    return result;
}

GOST::Cipher::bytes_t GOST::Cipher::EncryptCFB(const bytes_t& message, uint64_t IV) {
    split_t ms = splitMessage(message);
    bytes_t result;
    for (auto it : ms) {
        IV = encrypt(IV) ^ it;
        auto bytes = toBytes(IV);
        result.insert(result.end(), bytes.begin(), bytes.end());
    }
    return result;
}

GOST::Cipher::bytes_t GOST::Cipher::DecryptCFB(const bytes_t& message, uint64_t IV) {
    split_t ms = splitMessage(message);
    bytes_t result;
    for (auto it : ms) {
        IV = encrypt(IV);
        auto bytes = toBytes(IV ^ it);
        result.insert(result.end(), bytes.begin(), bytes.end());
        IV = it;
    }
    return result;
}

GOST::Cipher::bytes_t GOST::Cipher::EncryptOFB(const bytes_t& message, uint64_t IV) {
    split_t ms = splitMessage(message);
    bytes_t result;
    for (auto it : ms) {
        IV = encrypt(IV);
        auto bytes = toBytes(IV ^ it);
        result.insert(result.end(), bytes.begin(), bytes.end());
    }
    return result;
}

GOST::Cipher::bytes_t GOST::Cipher::DecryptOFB(const bytes_t& message, uint64_t IV) {
    return EncryptOFB(message, IV);
}

std::bitset<256> GOST::Cipher::genKey(unsigned int seed = 0) {
    srand(seed);
    std::bitset<256> result(0);
    for (int i = 0; i < 256; ++i)
        result.set(i, rand() % 2);
    return result;
}

GOST::Cipher::blocks_t GOST::Cipher::genBlocks(unsigned int seed) {
    blocks_t result;
    block_t nums = { { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 } };
    for (int i = 0; i < 8; ++i) {
        std::shuffle(nums.begin(), nums.end(), std::default_random_engine(seed));
        result[i] = nums;
    }
    return result;
}

GOST::Cipher::split_t GOST::Cipher::splitMessage(const bytes_t& bytes) {
    bytes_t expbytes = bytes;
    for (int i = 0; i < 8 * std::ceil(bytes.size() / 8.0) - bytes.size(); ++i)
        expbytes.push_back(0);
    split_t result;
    for (auto it = expbytes.begin(); it != expbytes.end(); it += 8)
        result.push_back(fromBytes<uint64_t>(&*it));
    return result;
}

uint32_t GOST::Cipher::f(uint32_t a, uint32_t key) {
    a += key;
    uint32_t r = 0;
    for (int i = 0; i < 8; ++i) {
        r |= blocks[i][a & 0xf] << i * 4;
        a >>= 4;
    }
    return (r << 11) | (r >> 21);
}

void GOST::Cipher::genStageKeys() {
    auto k = key;
    for (int i = 1; i <= 8; ++i) {
        stage_keys[i - 1] = (k & key_t(0xffffffff)).to_ulong();
        k >>= 32;
    }
}

uint64_t GOST::Cipher::encrypt(uint64_t m) {
    uint32_t b = m >> 32, a = m & 0xffffffff;
    for (int i = 0; i < 31; ++i) {
        uint32_t t = b ^ f(a, stage_keys[i < 24 ? i % 8 : 7 - (i % 8)]);
        b = a;
        a = t;
    }
    b = b ^ f(a, stage_keys[0]);
    return (static_cast<uint64_t>(b)) << 32 | a;
}

uint64_t GOST::Cipher::decrypt(uint64_t m) {
    uint32_t b = m >> 32, a = m & 0xffffffff;
    for (int i = 0; i < 31; ++i) {
        uint32_t t = b ^ f(a, stage_keys[i < 8 ? i % 8 : 7 - (i % 8)]);
        b = a;
        a = t;
    }
    b = b ^ f(a, stage_keys[0]);
    return (static_cast<uint64_t>(b)) << 32 | a;
}


