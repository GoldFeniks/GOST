#pragma once
#include <ctime>
#include <bitset>
#include <array>
#include <vector>
#include <string>

namespace GOST {

    class Cipher {

    public:

        typedef unsigned char byte_t;
        typedef std::vector<byte_t> bytes_t;
        typedef unsigned int seed_t;
        typedef std::array<uint32_t, 16> block_t;
        typedef std::array<block_t, 8> blocks_t;
        typedef std::bitset<256> key_t;

        Cipher(key_t key, blocks_t blocks) : key(key), blocks(blocks) { genStageKeys(); };
        Cipher(key_t key) : key(key), blocks(genBlocks(time(NULL))) { genStageKeys(); };
        Cipher(blocks_t blocks) : key(genKey(time(NULL))), blocks(blocks) { genStageKeys(); };
        Cipher(seed_t key_seed = 0, seed_t blocks_seed = 0) : key(genKey(key_seed)), blocks(genBlocks(blocks_seed)) { genStageKeys(); };
        Cipher() : key(genKey(time(NULL))), blocks(genBlocks(time(NULL))) { genStageKeys(); };

        bytes_t EncryptECB(const bytes_t& message);
        bytes_t DecryptECB(const bytes_t& message);

        bytes_t EncryptCBC(const bytes_t& message, uint64_t IV);
        bytes_t DecryptCBC(const bytes_t& message, uint64_t IV);

        bytes_t EncryptCFB(const bytes_t& message, uint64_t IV);
        bytes_t DecryptCFB(const bytes_t& message, uint64_t IV);

    private:

        typedef std::array<uint32_t, 8> stage_keys_t;
        typedef std::vector<uint64_t> split_t;

        static key_t genKey(unsigned int seed);
        static blocks_t genBlocks(unsigned int seed);
        static split_t splitMessage(const bytes_t& bytes);

        uint32_t f(uint32_t a, uint32_t key);
        void genStageKeys();
        uint64_t encrypt(uint64_t m);
        uint64_t decrypt(uint64_t m);

        key_t key;
        stage_keys_t stage_keys;
        blocks_t blocks;

        template<typename T>
        static std::array<byte_t, sizeof(T)> toBytes(T value) {
            std::array<byte_t, sizeof(T)> result;
            for (int i = 0; i < sizeof(T); ++i) {
                result[i] = value & 0xff;
                value >>= 8;
            }
            return result;
        }

        template<typename T>
        static T fromBytes(const byte_t* bytes) {
            T t = 0;
            for (int i = 0; i < sizeof(T); ++i) {
                t |= static_cast<T>(*bytes) << i * 8;
                ++bytes;
            }
            return t;
        }

    };// class Cipher

}// GOST
