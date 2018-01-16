#include "cipher.hpp"
#include <random>
#include <cmath>

gost_magma::cipher::bytes_t gost_magma::cipher::encrypt_ecb(const bytes_t& message) {
    auto ms = split_message(message);
    bytes_t result;
    for (auto it : ms) {
        auto bytes = to_bytes(encrypt_(this, it));
        result.insert(result.end(), bytes.begin(), bytes.end());
    }
    return result;
}

gost_magma::cipher::bytes_t gost_magma::cipher::decrypt_ecb(const bytes_t& message) {
    auto ms = split_message(message);
    bytes_t result;
    for (auto it : ms) {
        auto bytes = to_bytes(decrypt_(this, it));
        result.insert(result.end(), bytes.begin(), bytes.end());
    }
    return result;
}

gost_magma::cipher::bytes_t gost_magma::cipher::encrypt_cbc(const bytes_t& message, initialization_vector_t iv) {
    auto ms = split_message(message);
    bytes_t result;
    for (auto it : ms) {
        iv = encrypt_(this, it ^ iv);
        auto bytes = to_bytes(iv);
        result.insert(result.end(), bytes.begin(), bytes.end());
    }
    return result;
}

gost_magma::cipher::bytes_t gost_magma::cipher::decrypt_cbc(const bytes_t& message, initialization_vector_t iv) {
    auto ms = split_message(message);
    bytes_t result;
    for (auto it : ms) {
        const auto t = decrypt_(this, it);
        auto bytes = to_bytes(t ^ iv);
        result.insert(result.end(), bytes.begin(), bytes.end());
        iv = it;
    }
    return result;
}

gost_magma::cipher::bytes_t gost_magma::cipher::encrypt_cfb(const bytes_t& message, initialization_vector_t iv) {
    auto ms = split_message(message);
    bytes_t result;
    for (auto it : ms) {
        iv = encrypt_(this, iv) ^ it;
        auto bytes = to_bytes(iv);
        result.insert(result.end(), bytes.begin(), bytes.end());
    }
    return result;
}

gost_magma::cipher::bytes_t gost_magma::cipher::decrypt_cfb(const bytes_t& message, initialization_vector_t iv) {
    auto ms = split_message(message);
    bytes_t result;
    for (auto it : ms) {
        iv = encrypt_(this, iv);
        auto bytes = to_bytes(iv ^ it);
        result.insert(result.end(), bytes.begin(), bytes.end());
        iv = it;
    }
    return result;
}

gost_magma::cipher::bytes_t gost_magma::cipher::encrypt_ofb(const bytes_t& message, initialization_vector_t iv) {
    auto ms = split_message(message);
    bytes_t result;
    for (auto it : ms) {
        iv = encrypt_(this, iv);
        auto bytes = to_bytes(iv ^ it);
        result.insert(result.end(), bytes.begin(), bytes.end());
    }
    return result;
}

gost_magma::cipher::bytes_t gost_magma::cipher::decrypt_ofb(const bytes_t& message, const initialization_vector_t iv) {
    return encrypt_ofb(message, iv);
}

std::bitset<256> gost_magma::cipher::gen_key(const unsigned int seed = 0) {
    srand(seed);
    std::bitset<256> result(0);
    for (auto i = 0; i < 256; ++i)
        result.set(i, rand() % 2);
    return result;
}

gost_magma::cipher::blocks_t gost_magma::cipher::gen_blocks(const unsigned int seed) {
    blocks_t result;
    block_t nums = { { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 } };
    for (auto i = 0; i < 8; ++i) {
        shuffle(nums.begin(), nums.end(), std::default_random_engine(seed));
        result[i] = nums;
    }
    return result;
}

gost_magma::cipher::split_t gost_magma::cipher::split_message(const bytes_t& bytes) {
    auto expbytes = bytes;
    for (auto i = 0; i < 8 * ceil(bytes.size() / 8.0) - bytes.size(); ++i)
        expbytes.push_back(0);
    split_t result;
    for (auto it = expbytes.begin(); it != expbytes.end(); it += 8)
        result.push_back(from_bytes<uint64_t>(&*it));
    return result;
}

uint32_t gost_magma::cipher::f(uint32_t a, const uint32_t key) {
    a += key;
    uint32_t r = 0;
    for (auto i = 0; i < 8; ++i) {
        r |= blocks_[i][a & 0xf] << i * 4;
        a >>= 4;
    }
    return r << 11 | r >> 21;
}

void gost_magma::cipher::gen_stage_keys() {
    auto k = key_;
    for (auto i = 1; i <= 8; ++i) {
        stage_keys_[i - 1] = (k & key_t(0xffffffff)).to_ulong();
        k >>= 32;
    }
}


