#pragma once
#include <ctime>
#include <bitset>
#include <array>
#include <vector>
#include <functional>

namespace gost_magma {

    class cipher {

    public:

        typedef unsigned char byte_t;
        typedef std::vector<byte_t> bytes_t;
        typedef unsigned int seed_t;
        typedef std::array<uint32_t, 16> block_t;
        typedef std::array<block_t, 8> blocks_t;
        typedef std::bitset<256> key_t;
        typedef uint64_t initialization_vector_t;
        typedef uint64_t message_part_t;

        cipher(const key_t key, const blocks_t blocks) : key_(key), blocks_(blocks) { gen_stage_keys(); }
        explicit cipher(const key_t key) : key_(key), blocks_(gen_blocks(time(nullptr))) { gen_stage_keys(); }
        explicit cipher(const blocks_t blocks) : key_(gen_key(time(nullptr))), blocks_(blocks) { gen_stage_keys(); }
        cipher(const seed_t key_seed, const seed_t blocks_seed) : key_(gen_key(key_seed)), blocks_(gen_blocks(blocks_seed)) { gen_stage_keys(); }
        cipher() : key_(gen_key(time(nullptr))), blocks_(gen_blocks(time(nullptr))) { gen_stage_keys(); };

        bytes_t encrypt_ecb(const bytes_t& message);
        bytes_t decrypt_ecb(const bytes_t& message);

        bytes_t encrypt_cbc(const bytes_t& message, initialization_vector_t iv);
        bytes_t decrypt_cbc(const bytes_t& message, initialization_vector_t iv);

        bytes_t encrypt_cfb(const bytes_t& message, initialization_vector_t iv);
        bytes_t decrypt_cfb(const bytes_t& message, initialization_vector_t iv);

        bytes_t encrypt_ofb(const bytes_t& message, initialization_vector_t iv);
        bytes_t decrypt_ofb(const bytes_t& message, initialization_vector_t iv);

        std::_Mem_fn<message_part_t(cipher::*)(message_part_t)> Encrypt = std::mem_fn(&cipher::encrypt<24>);
        std::_Mem_fn<message_part_t(cipher::*)(message_part_t)> Decrypt = std::mem_fn(&cipher::encrypt<8>);
        
    private:

        typedef std::array<uint32_t, 8> stage_keys_t;
        typedef std::vector<uint64_t> split_t;

        static key_t gen_key(unsigned int seed);
        static blocks_t gen_blocks(unsigned int seed);
        static split_t split_message(const bytes_t& bytes);

        uint32_t f(uint32_t a, uint32_t key);
        void gen_stage_keys();

        key_t key_;
        stage_keys_t stage_keys_;
        blocks_t blocks_;

        template<typename T>
        static std::array<byte_t, sizeof(T)> to_bytes(T value) {
            std::array<byte_t, sizeof(T)> result;
            for (auto i = 0; i < sizeof(T); ++i) {
                result[i] = value & 0xff;
                value >>= 8;
            }
            return result;
        }

        template<typename T>
        static T from_bytes(const byte_t* bytes) {
            T t = 0;
            for (auto i = 0; i < sizeof(T); ++i) {
                t |= static_cast<T>(*bytes) << i * 8;
                ++bytes;
            }
            return t;
        }

        template<size_t I>
        message_part_t encrypt(const message_part_t m) {
            uint32_t b = m >> 32, a = m & 0xffffffff;
            for (auto i = 0; i < 32; ++i) {
                auto t = b ^ f(a, stage_keys_[i < I ? i % 8 : 7 - i % 8]);
                b = a;
                a = t;
            }
            return static_cast<message_part_t>(a) << 32 | b;
        }


    };// class Cipher

}// namespace gost_magma
