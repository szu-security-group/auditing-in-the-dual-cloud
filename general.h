#pragma once
#include <iostream>
#include <string>
#include "timer.h"

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

constexpr auto BLOCK_SIZE = 4;
constexpr auto M_AES_BLOCK_SIZE = 16;
constexpr auto BUFFER_SIZE = 4096;
constexpr auto KEY_SIZE = 16;
constexpr auto DIGEST_SIZE = 1;
// challenge length 460(688) leads to 99% (99.9%) a successful detection probability
// if 1% outsourced data is damaged.
// constexpr auto CHALLENGE_NUM = 460;
// constexpr auto CHALLENGE_NUM = 688;
constexpr auto file_path = "../data/100MB";
typedef unsigned long long block;

extern timer hash2_time;

void test_salsa20_stream();

void inner_hash(const std::string &file_str, const uint8_t *key, uint8_t *digest);
void indexless_hash(std::string file_str, const uint8_t *key, uint8_t *digest);
unsigned long long int Hash1_v2(const uint8_t *key);
unsigned long long int hash1_v3(const uint8_t *key);

void print_buffer(const uint8_t *pointer);

void print_box(const uint8_t *box);

void print_bytes(const uint8_t *pointer, int length);

std::string binaryToHex(std::string binaryStr);

void PRF(const std::string &file_str, const uint8_t *key, std::string &prf_output);

void Hash1_v1(const std::string &file_str, const uint8_t *key, uint8_t *digest);

std::string hmacSha1(const std::string &key, const std::string &message);

std::string hmacSha256(const std::string &key, const std::string &message);

std::string calculateHmacSha256(const std::string &filename, const std::string &key);
std::string calculateHmacSha1(const std::string &filename, const std::string &key);

unsigned int get_challenge_num(long long unsigned file_blocks, const double success_prob, const double error_prob);

std::string generateRandomKey(int keySize);

std::string readFileToString(const std::string &filename);

void save_key_dig(const std::string& save_path,const uint8_t *key,int key_len,const uint8_t *dig,int dig_len);

std::string Hash2(const std::string &filename, const std::string &key);

unsigned long long inner_hash(const std::string &file_str,const uint8_t*key);
 