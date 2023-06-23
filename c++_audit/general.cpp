#include "general.h"
#include "rijndael.h"
#include "gfmul.h"
#include <stdio.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <filesystem>
#include "rc4.h"
#include <crypto870/cryptlib.h>
#include <crypto870/salsa.h>
#include <crypto870/files.h>

void print_buffer(const uint8_t* pointer)
{

    for (int i = 0; i < BUFFER_SIZE; i++)
        printf("%02x ", pointer[i]);
    printf("\n");
}

void print_box(const uint8_t* box)
{
    for (int i = 0; i < 256; i++) {
        printf("%02x ", box[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
}

void print_bytes(const uint8_t* pointer, int length)
{
    for (int i = 0; i < length; i++) {
        printf("%02x ", pointer[i]);
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
    }
}

block multiply_sum(block* a, block* b, int length) {
    block sum = 0;
    for (int i = 0; i < length; i = i + 1) {
        sum = sum + a[i] * b[i];
    }
    return sum;
}

void test_salsa20_stream()
{
    using namespace CryptoPP;
    Salsa20::Encryption enc;
    uint8_t key[16] = { 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t iv[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    enc.SetKeyWithIV(key, 16, iv, 8);
    uint8_t plaintext[64] = {};
    uint8_t ciphertext[64] = {};
    enc.ProcessData(ciphertext, plaintext, 64);
    uint8_t plaintext1[64] = {};
    uint8_t ciphertext1[64] = {};
    enc.ProcessData(ciphertext1, plaintext1, 64);
    print_bytes(ciphertext, 64);
    print_bytes(ciphertext1, 64);
}

///****************************************************************************                 
/// @brief   : return digest by computing inner product of file stream
/// file_str : file_stream                                                           
///****************************************************************************
void sample_hash(std::string file_str, const uint8_t* key, uint8_t* digest) {
    unsigned long long* p = (unsigned long long*) & file_str[0];
    int count = 0;
    long long unsigned sum = 0;
    uint8_t* box = NULL;
    uint8_t* buffer = new uint8_t[BUFFER_SIZE];
    block* key_list = (block*)buffer;
    int key_list_size = BUFFER_SIZE / BLOCK_SIZE;
    size_t str_length = file_str.length();
    int last_num = str_length % BUFFER_SIZE / BLOCK_SIZE;
    size_t num = str_length / BUFFER_SIZE;

    // use rc4 generate random number
    rc4 rc4_ = rc4(key, KEY_SIZE);
    while (true) {
        rc4_.rc4keystream(buffer,BUFFER_SIZE);
        if (count < num) {
            sum = sum + multiply_sum(key_list, p, key_list_size);
        }
        else {
            sum = sum + multiply_sum(key_list, p, last_num);
            break;
        }
        count++;
        p = (unsigned long long*) & file_str[BUFFER_SIZE * count];
    }
    // use salsa20 generate random number
    /*
    CryptoPP::Salsa20::Encryption enc;
    uint8_t iv[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    enc.SetKeyWithIV(key, 16, iv, 8);
    uint8_t input[BUFFER_SIZE]{};
    memset(input, 0, BUFFER_SIZE);
    while (true) {
        enc.ProcessData(buffer, input, BUFFER_SIZE);
        if (count < num) {
            sum = sum + multiply_sum(key_list, p, key_list_size);
        }
        else {
            sum = sum + multiply_sum(key_list, p, last_num);
            break;
        }
        count++;
        p = (unsigned long long*) & file_str[BUFFER_SIZE * count];
    }*/
    

    delete []buffer;
    uint8_t *tmp = (uint8_t*)&sum;
    for (int i = 0; i < BLOCK_SIZE; i++) {
        digest[i] = tmp[i];
    }
}

///****************************************************************************                 
/// @brief   : return digest that supports dynamic update in GF(2^128)
/// file_str : file_stream                                                           
///****************************************************************************
void indexless_hash(std::string file_str, const uint8_t* key, uint8_t* digest)
{
    auto length = file_str.length();
    auto numBlock = length / AES_BLOCK_SIZE;
    uint8_t* fp = (uint8_t*) & file_str[0];
    uint8_t Encypted_block[AES_BLOCK_SIZE]{};
    __m128i bswap_mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
    __m128i cur_block, coefficient, product, result= _mm_setzero_si128();
    rijndael cipher = rijndael(key);
    for (int i = 0; i < numBlock-1; i++) {
        cur_block = _mm_loadu_si128((__m128i*)fp);
        cur_block = _mm_shuffle_epi8(cur_block, bswap_mask);
        // point to next block
        fp = fp + AES_BLOCK_SIZE;
        cipher.encrypt(fp,Encypted_block);
        coefficient = _mm_loadu_si128((__m128i*)Encypted_block);
        coefficient = _mm_shuffle_epi8(coefficient, bswap_mask);
        gfmul_(cur_block,coefficient,&product);
        product = _mm_shuffle_epi8(product, bswap_mask);
        result = _mm_xor_si128(result, product);
    }
    _mm_storeu_si128((__m128i*)digest, result);

}


std::string binaryToHex(std::string binaryStr)
{
    std::string ret;
    static const char* hex = "0123456789ABCDEF";
    for (auto c : binaryStr)
    {
        ret.push_back(hex[(c >> 4) & 0xf]); //取二进制高四位
        ret.push_back(hex[c & 0xf]);        //取二进制低四位
    }
    return ret;
}

