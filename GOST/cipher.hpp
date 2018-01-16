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

        /**
         * \brief initialize cipher with specified key and s-blocks
         * \param key 256 bit key
         * \param blocks s-blocks
         */
        cipher(const key_t key, const blocks_t blocks) : key_(key), blocks_(blocks) { gen_stage_keys(); }

        /**
         * \brief initialize cipher with specified key and random s-blocks
         * \param key 256 bit key
         */
        explicit cipher(const key_t key) : key_(key), blocks_(gen_blocks(time(nullptr))) { gen_stage_keys(); }

        /**
         * \brief initialize cipher with specified s-blocks and random key
         * \param blocks 
         */
        explicit cipher(const blocks_t blocks) : key_(gen_key(time(nullptr))), blocks_(blocks) { gen_stage_keys(); }

        /**
         * \brief initialize cipher with random key and s-blocks using specified seeds
         * \param key_seed seed to be used for key generation
         * \param blocks_seed seed to be used for s-blocks generation
         */
        cipher(const seed_t key_seed, const seed_t blocks_seed) : key_(gen_key(key_seed)), blocks_(gen_blocks(blocks_seed)) { gen_stage_keys(); }

        /**
         * \brief initialize cipher with random key and s-blocks
         */
        cipher() : key_(gen_key(time(nullptr))), blocks_(gen_blocks(time(nullptr))) { gen_stage_keys(); };

        /**
         * \brief encrypt message using electronic codebook mode of operation
         * \param message bytes to be encrypted
         * \return encrypted bytes
         */
        bytes_t encrypt_ecb(const bytes_t& message);

        /**
        * \brief decrypt message using electronic codebook mode of operation
        * \param message bytes to be decrypted
        * \return decrypted bytes
        */
        bytes_t decrypt_ecb(const bytes_t& message);

        /**
         * \brief encrypt message using cipher block chain mode of operation
         * \param message bytes to be encrypted
         * \param iv initialization vector to be used in encryption
         * \return encrypted bytes
         */
        bytes_t encrypt_cbc(const bytes_t& message, initialization_vector_t iv);

        /**
        * \brief decrypt message using cipher block chain mode of operation
        * \param message bytes to be decrypted
        * \param iv initialization vector to be used in decryption
        * \return decrypted bytes
        */
        bytes_t decrypt_cbc(const bytes_t& message, initialization_vector_t iv);

        /**
        * \brief encrypt message using cipher feedback mode of operation
        * \param message bytes to be encrypted
        * \param iv initialization vector to be used in encryption
        * \return encrypted bytes
        */
        bytes_t encrypt_cfb(const bytes_t& message, initialization_vector_t iv);

        /**
        * \brief decrypt message using cipher feedback mode of operation
        * \param message bytes to be dencrypted
        * \param iv initialization vector to be used in decryption
        * \return decrypted bytes
        */
        bytes_t decrypt_cfb(const bytes_t& message, initialization_vector_t iv);

        /**
        * \brief encrypt message using output feedback mode of operation
        * \param message bytes to be encrypted
        * \param iv initialization vector to be used in encryption
        * \return encrypted bytes
        */
        bytes_t encrypt_ofb(const bytes_t& message, initialization_vector_t iv);

        /**
        * \brief decrypt message using output feedback mode of operation
        * \param message bytes to be decrypted
        * \param iv initialization vector to be used in decryption
        * \return decrypted bytes
        */
        bytes_t decrypt_ofb(const bytes_t& message, initialization_vector_t iv);

        /**
        * \brief generate random key
        * \param seed seed to be used for generation
        * \return generated key
        */
        static key_t gen_key(unsigned int seed);

        /**
        * \brief generate random s-blocks
        * \param seed seed to be used for generation
        * \return generated s-blocks
        */
        static blocks_t gen_blocks(unsigned int seed);
        
    private:

        typedef std::array<uint32_t, 8> stage_keys_t;
        typedef std::vector<message_part_t> split_t;

        /**
         * \brief cipher key
         */
        key_t key_;

        /**
         * \brief cipher stage keys
         */
        stage_keys_t stage_keys_;

        /**
         * \brief cipher s-blocks
         */
        blocks_t blocks_;

        /**
         * \brief split message in 64bit numbers and perfrom padding if necessary 
         * \param bytes message to be splitted
         * \param do_padding pass true to perform padding
         * \return splitted message
         */
        static split_t split_message(const bytes_t& bytes, const bool do_padding = true);

        /**
         * \brief drop extra bytes added after padding (in place)
         * \param bytes bytes for processing
         * \return passed bytes
         */
        static bytes_t& drop_bytes(bytes_t& bytes);

        /**
         * \brief generate stage keys
         */
        void gen_stage_keys();

        /**
         * \brief function f used in Feistel network
         * \param a lower bits of message part
         * \param key round key
         * \return function result
         */
        uint32_t f(uint32_t a, uint32_t key);

        /**
         * \brief splits value in bytes
         * \tparam T type of value to be splitted
         * \param value value to be splitted
         * \return splitted value
         */
        template<typename T>
        static std::array<byte_t, sizeof(T)> to_bytes(T value) {
            std::array<byte_t, sizeof(T)> result;
            for (auto i = 0; i < sizeof(T); ++i) {
                result[i] = value & 0xff;
                value >>= 8;
            }
            return result;
        }

        /**
         * \brief converts bytes into value of type T
         * \tparam T type of result value
         * \param bytes bytes to be converted
         * \return converted bytes
         */
        template<typename T>
        static T from_bytes(const byte_t* bytes) {
            T t = 0;
            for (auto i = 0; i < sizeof(T); ++i) {
                t |= static_cast<T>(*bytes) << i * 8;
                ++bytes;
            }
            return t;
        }

        /**
         * \brief perform cipher encryption passing first I stage keys in straight order
         * \tparam I number of stage keys to be passed in straight order
         * \param m value to be encrypted
         * \return encrypted value
         */
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

        /**
         * \brief perform encryption
         * \param 1 value to be encrypted
         */
        std::_Mem_fn<message_part_t(cipher::*)(message_part_t)> encrypt_ = std::mem_fn(&cipher::encrypt<24>);

        /**
        * \brief perform decryption
        * \param 1 value to be decrypted
        */
        std::_Mem_fn<message_part_t(cipher::*)(message_part_t)> decrypt_ = std::mem_fn(&cipher::encrypt<8>);


    };// class Cipher

}// namespace gost_magma
