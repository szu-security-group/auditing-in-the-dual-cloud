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
#include <cryptopp/cryptlib.h>
#include <cryptopp/salsa.h>
#include <cryptopp/files.h>
#include <cryptopp/chacha.h>
#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>
#include <cryptopp/chacha.h>
#include <cryptopp/md5.h>
#include <cryptopp/sm3.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include "timer.h"

using namespace std;

timer c_hash1_time = timer("hash1");
timer hash2_time = timer("hash2");

void print_buffer(const uint8_t *pointer)
{

  for (int i = 0; i < BUFFER_SIZE; i++)
    printf("%02x ", pointer[i]);
  printf("\n");
}

void print_box(const uint8_t *box)
{
  for (int i = 0; i < 256; i++)
  {
    printf("%02x ", box[i]);
    if ((i + 1) % 16 == 0)
    {
      printf("\n");
    }
  }
}

void print_bytes(const uint8_t *pointer, int length)
{
  for (int i = 0; i < length; i++)
  {
    printf("%02x ", pointer[i]);
    if ((i + 1) % 16 == 0)
    {
      printf("\n");
    }
  }
}

block multiply_sum(block *a, unsigned int *b, int length)
{
  block sum = 0;
  for (int i = 0; i < length; i = i + 1)
  {
    sum = sum + a[i] * b[i];
  }
  return sum;
}

void test_salsa20_stream()
{
  using namespace CryptoPP;
  Salsa20::Encryption enc;
  uint8_t key[16] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  uint8_t iv[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
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
/*
unsigned long long inner_hash(const std::string &file_str,const uint8_t*key){
  int length = file_str.length();
  // CryptoPP::Salsa20::Encryption enc;
  CryptoPP::ChaCha::Encryption enc;
  uint8_t iv[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  enc.SetKeyWithIV(key, 32, iv, 8);
  uint8_t input[length*2]{};
  enc.ProcessData(input, input, length*2);
  unsigned long long sum = 0;
  unsigned long long  *p1 = (unsigned long long*) file_str.data();
  unsigned long long *p2 = (unsigned long long*) input;
  
  for(int i=0;i<length/(BLOCK_SIZE);i++){
    sum += p1[i]*p2[i];
  }

  return 0;
}*/

unsigned long long inner_hash(const std::string &file_str,const uint8_t*key){
  int length = file_str.length();
  // CryptoPP::Salsa20::Encryption enc;
  CryptoPP::ChaCha::Encryption enc;
  uint8_t iv[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; 
  enc.SetKeyWithIV(key, 32, iv, 8);
  uint8_t input[2*1024*1024]{};// 1MB字节空间
  unsigned long long sum = 0;
  unsigned int *p1 = (unsigned int*) file_str.data();
  unsigned long long *p2 = (unsigned long long*) input;
  int count = length/(1024*1024);
  for(int i=0;i<count;i++){
  enc.ProcessData(input, input, 2*1024*1024);
  for(int i=0;i<1024*1024/BLOCK_SIZE;i++){
  sum += *p1*input[i];
  }
  }
 return 0;
}


///****************************************************************************
/// @brief   : return digest by computing inner product of file stream
/// file_str : file_stream
///****************************************************************************
void inner_hash(const std::string &file_str, const uint8_t *key, uint8_t *digest)
{
  using namespace CryptoPP;
  long long unsigned sum = 0;
  uint8_t *buffer = new uint8_t[BUFFER_SIZE];
  unsigned int *p = (unsigned int *)&file_str[0];
  size_t count = 0;
  uint8_t *box = NULL;
  block *key_list = (block *)buffer;
  int key_list_size = BUFFER_SIZE / BLOCK_SIZE;
  size_t str_length = file_str.length();
  int last_num = str_length % BUFFER_SIZE / BLOCK_SIZE;
  size_t num = str_length / BUFFER_SIZE;

  // use rc4 generate random number
  /*
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
  */
  // use salsa20 generate random number

  CryptoPP::Salsa20::Encryption enc;
  uint8_t iv[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  enc.SetKeyWithIV(key, 16, iv, 8);
  uint8_t input[BUFFER_SIZE*2]{};
  memset(input, 0, BUFFER_SIZE);
  hash2_time.set_start();
  while (true)
  {
    enc.ProcessData(input, input, BUFFER_SIZE*2);
    if (count < num)
    {
      sum = sum + multiply_sum(key_list, p, key_list_size);
    }
    else
    {
      sum = sum + multiply_sum(key_list, p, last_num);
      break;
    }
    
    count++;
    p = (unsigned int *)&file_str[BUFFER_SIZE * count];
  }
  hash2_time.set_end();

  // use chacha generate random num
  /*
  CryptoPP::ChaCha::Encryption enc;
  uint8_t iv[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
  enc.SetKeyWithIV(key, 16, iv);
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
  }
  */
  /*
  uint8_t hamc[CryptoPP::SHA256::DIGESTSIZE];
  HMAC<SHA256> hmacGenerator(key, 16);
  hmacGenerator.Update((const uint8_t*)file_str.data(), file_str.size());
  hmacGenerator.Final(hamc);
  */

  /*
  SM3 sm3_hash;
  uint8_t sm3_digest[SM3::DIGESTSIZE];
  sm3_hash.Update((const uint8_t*)file_str.data(), file_str.size());
  sm3_hash.Final(sm3_digest);
  */

  delete[] buffer;
  uint8_t *tmp = (uint8_t *)&sum;
  memcpy(digest, tmp, BLOCK_SIZE);
}

///****************************************************************************
/// @brief   : return digest that supports dynamic update in GF(2^128)
/// file_str : file_stream
///****************************************************************************
void indexless_hash(std::string file_str, const uint8_t *key, uint8_t *digest)
{
  auto length = file_str.length();
  auto numBlock = length / AES_BLOCK_SIZE;
  uint8_t *fp = (uint8_t *)&file_str[0];
  uint8_t Encypted_block[AES_BLOCK_SIZE]{};
  __m128i bswap_mask = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
  __m128i cur_block, coefficient, product, result = _mm_setzero_si128();
  rijndael cipher = rijndael(key);
  for (unsigned long long i = 0; i < numBlock - 1; i++)
  {
    cur_block = _mm_loadu_si128((__m128i *)fp);
    cur_block = _mm_shuffle_epi8(cur_block, bswap_mask);
    // point to next block
    fp = fp + AES_BLOCK_SIZE;
    cipher.encrypt(fp, Encypted_block);
    coefficient = _mm_loadu_si128((__m128i *)Encypted_block);
    coefficient = _mm_shuffle_epi8(coefficient, bswap_mask);
    gfmul_(cur_block, coefficient, &product);
    product = _mm_shuffle_epi8(product, bswap_mask);
    result = _mm_xor_si128(result, product);
  }
  _mm_storeu_si128((__m128i *)digest, result);
}

std::string binaryToHex(std::string binaryStr)
{
  std::string ret;
  static const char *hex = "0123456789ABCDEF";
  for (auto c : binaryStr)
  {
    ret.push_back(hex[(c >> 4) & 0xf]); // ȡ�����Ƹ���λ
    ret.push_back(hex[c & 0xf]);        // ȡ�����Ƶ���λ
  }
  return ret;
}

void PRF(const std::string &file_str, const uint8_t *key, std::string &prf_output)
{
  const uint8_t *fp = reinterpret_cast<const uint8_t *>(file_str.data());
  size_t length = file_str.length();
  size_t numBlocks = length / BLOCK_SIZE;

  rijndael cipher = rijndael(key);
  prf_output.reserve(2 * numBlocks * BLOCK_SIZE);
  uint8_t encrypted_block[AES_BLOCK_SIZE];
  uint8_t input_block[AES_BLOCK_SIZE];
  for (size_t i = 0; i < numBlocks - 2; i++)
  {
    memset(input_block, 0, AES_BLOCK_SIZE);
    memcpy(input_block, fp, BLOCK_SIZE * 3);
    cipher.encrypt(input_block, encrypted_block);
    prf_output.append(reinterpret_cast<const char *>(encrypted_block + 2*BLOCK_SIZE), 2*BLOCK_SIZE);
    fp += BLOCK_SIZE;
  }
}
/// @brief proproceess message then hash
/// @param key 
/// @return digest
unsigned long long int Hash1_v2(const uint8_t *key)
{
  std::ifstream infile(file_path, std::ios::in | std::ios::binary);
  std::stringstream file_str_stream;
  uint8_t local_digest[BLOCK_SIZE]{};
  unsigned long long _file_size = std::filesystem::file_size(file_path);
  int padding_length = BLOCK_SIZE - _file_size % BLOCK_SIZE;
  unsigned long long int sum = 0;
  file_str_stream << infile.rdbuf();
  // padding stream to 0...01
  if (padding_length != BLOCK_SIZE)
    file_str_stream << std::setfill((char)0) << std::setw(padding_length - 1) << (char)1;
  unsigned int f_size = (unsigned int)_file_size;
  file_str_stream.write(reinterpret_cast<char *>(&f_size), sizeof(f_size));
  constexpr size_t BUFFER_SIZE = BLOCK_SIZE * 8912;
  CryptoPP::byte buffer[BUFFER_SIZE];
  unsigned int *pr = reinterpret_cast<unsigned int *>(buffer), *tpr;
  CryptoPP::Rijndael::Encryption encryption(key, 16);
  uint8_t input_block[AES_BLOCK_SIZE], output_block[AES_BLOCK_SIZE];
  unsigned int *coeff = (unsigned int *)output_block;
  AES_KEY aesKey;
  AES_set_encrypt_key(key, 128, &aesKey);
  int read_block_num;
  while (true)
  {
    file_str_stream.read(reinterpret_cast<char *>(buffer), BUFFER_SIZE);
    tpr = pr;
    read_block_num = file_str_stream.gcount() / BLOCK_SIZE - 2;
    for (uint16_t i = 0; i < read_block_num; i++)
    {
      memset(input_block + BLOCK_SIZE * 3, 0, BLOCK_SIZE);
      memcpy(input_block, buffer + i * BLOCK_SIZE, BLOCK_SIZE * 3);
      AES_encrypt(input_block, output_block, &aesKey);
      sum += *tpr * (*coeff);
      tpr++;
    }
    if (!file_str_stream.good())
      break;
    file_str_stream.seekg(-2 * BLOCK_SIZE, std::ios::cur);
  }
  return sum;
}

/// @brief when need padding, padding string
/// @param key 
/// @return 
/*
unsigned long long int hash1_v3(const uint8_t *key)
{
  std::ifstream infile(file_path, std::ios::in | std::ios::binary);
  uint8_t local_digest[BLOCK_SIZE]{};
  unsigned long long _file_size = std::filesystem::file_size(file_path);
  int padding_length = BLOCK_SIZE - _file_size % BLOCK_SIZE;
  unsigned long long int sum = 0;
  unsigned int f_size = (unsigned int)_file_size;
  constexpr size_t BUFFER_SIZE = BLOCK_SIZE * 8912;
  CryptoPP::byte buffer[BUFFER_SIZE];
  unsigned int *pr = reinterpret_cast<unsigned int *>(buffer), *tpr;
  CryptoPP::Rijndael::Encryption encryption(key, 16);
  uint8_t input_block[AES_BLOCK_SIZE], output_block[AES_BLOCK_SIZE];
  unsigned int *coeff = (unsigned int *)output_block;
  AES_KEY aesKey;
  AES_set_encrypt_key(key, 128, &aesKey);
  int read_block_num;
  c_hash1_time.set_start();
  while (true)
  {
    infile.read(reinterpret_cast<char *>(buffer), BUFFER_SIZE);
    tpr = pr;
    read_block_num = infile.gcount() / BLOCK_SIZE - 2;
    for (uint16_t i = 0; i < read_block_num; i++)
    {
      memset(input_block + 3, 0, BLOCK_SIZE);
      memcpy(input_block, tpr, BLOCK_SIZE * 3);
      AES_encrypt(input_block, output_block, &aesKey);
      tpr++;
      sum += *tpr * (*coeff);
    }
    if (!infile.good())
      break;
    infile.seekg(-2 * BLOCK_SIZE, std::ios::cur);
  }
  c_hash1_time.set_end();
  std::cout<<"hash1 cost time"<<std::endl;
  c_hash1_time.cal_average_duration(Nanoseconds);
  save_key_dig("../data/key_dig.txt",key,16,(uint8_t*)&sum,8);
  return sum;
}
*/

unsigned long long int hash1_v3(const uint8_t *key)
{
  std::ifstream infile(file_path, std::ios::in | std::ios::binary);
  uint8_t local_digest[BLOCK_SIZE]{};
  unsigned long long _file_size = std::filesystem::file_size(file_path);
  unsigned long long int sum = 0;
  unsigned int f_size = (unsigned int)_file_size;
  constexpr size_t BUFFER_SIZE = BLOCK_SIZE * 8912;
  alignas(4) CryptoPP::byte buffer[BUFFER_SIZE];
  unsigned int *pr = reinterpret_cast<unsigned int *>(buffer), *tpr;
  CryptoPP::Rijndael::Encryption encryption(key, 16);
  uint8_t output_block[AES_BLOCK_SIZE];
  __m128i i_b;
  uint8_t* input_block = (uint8_t*)&i_b;
  unsigned int *coeff = (unsigned int *)output_block;
  AES_KEY aesKey;
  AES_set_encrypt_key(key, 128, &aesKey);
  int read_block_num;
  while (true)
  {
    infile.read(reinterpret_cast<char *>(buffer), BUFFER_SIZE);
    c_hash1_time.set_start();
    tpr = pr;
    read_block_num = infile.gcount() / BLOCK_SIZE - 2;
    for (uint16_t i = 0; i < read_block_num; i++)
    {
      memset(input_block + 3, 0, BLOCK_SIZE);
      memcpy(input_block, tpr, BLOCK_SIZE * 3);
      AES_encrypt(input_block, output_block, &aesKey);
      tpr++;
      sum += *tpr * (*coeff);
    }
    c_hash1_time.set_end();
    if (!infile.good())
      break;
    infile.seekg(-2 * BLOCK_SIZE, std::ios::cur);
  }
  // process last two block
  infile.seekg((f_size/BLOCK_SIZE-2)*BLOCK_SIZE,std::ios::beg);
  c_hash1_time.set_start();
  infile.read(reinterpret_cast<char*>(buffer),BUFFER_SIZE);
  memcpy(buffer+2*BLOCK_SIZE,&f_size,BLOCK_SIZE);
  memcpy(buffer+3*BLOCK_SIZE,&f_size,BLOCK_SIZE);
  tpr = pr;
  for (uint16_t i = 0; i < 2; i++)
  {
    memset(input_block + 3, 0, BLOCK_SIZE);
    memcpy(input_block, tpr, BLOCK_SIZE * 3);
    AES_encrypt(input_block, output_block, &aesKey);
    tpr++;
    sum += *tpr * (*coeff);
  }
  c_hash1_time.set_end();
  c_hash1_time.cal_sum_time(Seconds);

  save_key_dig("../data/key_dig.txt",key,16,(uint8_t*)&sum,8);
  return sum;
}

void Hash1_v1(const std::string &file_str, const uint8_t *key, uint8_t *digest)
{
  unsigned long long int sum = 0;
  // timer t_time = timer();
  // t_time.set_start();
  std::string prf_str;
  auto block_num = file_str.length() / BLOCK_SIZE - 2;
  PRF(file_str, key, prf_str);
  // t_time.set_end();
  // t_time.compute_duration();
  // t_time.print_time_cost();

  // t_time.set_start();
  unsigned int *pf = (unsigned int *)&file_str[0];
  unsigned long long *pp = (unsigned long long *)&prf_str[0];
  for (unsigned long long i = 0; i < block_num - 2; i++)
  {
    sum += *pf * *pp;
    ++pf;
    ++pp;
    // cout<<i<<endl;
  }
  // memcpy(digest, &sum, BLOCK_SIZE);
  // t_time.set_end();
  // t_time.compute_duration();
  // t_time.print_time_cost();
}

unsigned int get_challenge_num(long long unsigned file_blocks, const double success_prob, const double error_prob)
{
  double error_blocks = file_blocks * error_prob;
  unsigned int i = 1;
  double cur_corr_prob = 1.0 * (file_blocks - error_blocks) / (file_blocks);
  while (cur_corr_prob > 1 - success_prob)
  {
    cur_corr_prob = cur_corr_prob * ((file_blocks - error_blocks - i) / (file_blocks - i));
    ++i;
  }
  return i;
}

std::string hmacSha1(const std::string &key, const std::string &message)
{
  CryptoPP::HMAC<CryptoPP::SHA1> hmac((const unsigned char *)key.data(), key.size());
  std::string digest;

  CryptoPP::StringSource(message, true,
                         new CryptoPP::HashFilter(hmac,
                                                  new CryptoPP::HexEncoder(
                                                      new CryptoPP::StringSink(digest))));

  return digest;
}

std::string hmacSha256(const std::string &key, const std::string &message)
{
  CryptoPP::HMAC<CryptoPP::SHA256> hmac((const unsigned char *)key.data(), key.size());
  std::string digest;

  CryptoPP::StringSource(message, true,
                         new CryptoPP::HashFilter(hmac,
                                                  new CryptoPP::HexEncoder(
                                                      new CryptoPP::StringSink(digest))));
  return digest;
}

std::string calculateHmacSha256(const std::string &filename, const std::string &key)
{
  std::ifstream file(filename, std::ios::binary);
  CryptoPP::HMAC<CryptoPP::SHA256> hmac(reinterpret_cast<const CryptoPP::byte *>(key.data()), key.size());

  constexpr size_t BUFFER_SIZE = 8192;
  CryptoPP::byte buffer[BUFFER_SIZE];
  while (file.good())
  {
    file.read(reinterpret_cast<char *>(buffer), BUFFER_SIZE);
    size_t bytesRead = file.gcount();
    hmac.Update(buffer, bytesRead);
  }
  file.close();

  CryptoPP::byte digest[CryptoPP::HMAC<CryptoPP::SHA256>::DIGESTSIZE];
  hmac.Final(digest);

  std::string result;
  CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(result));
  encoder.Put(digest, sizeof(digest));
  encoder.MessageEnd();

  return result;
}

std::string calculateHmacSha1(const std::string &filename, const std::string &key)
{
  std::ifstream file(filename, std::ios::binary);
  CryptoPP::HMAC<CryptoPP::SHA1> hmac(reinterpret_cast<const CryptoPP::byte *>(key.data()), key.size());

  constexpr size_t BUFFER_SIZE = 8192;
  CryptoPP::byte buffer[BUFFER_SIZE];
  while (file.good())
  {
    file.read(reinterpret_cast<char *>(buffer), BUFFER_SIZE);
    size_t bytesRead = file.gcount();
    hmac.Update(buffer, bytesRead);
  }
  file.close();

  CryptoPP::byte digest[CryptoPP::HMAC<CryptoPP::SHA256>::DIGESTSIZE];
  hmac.Final(digest);

  std::string result;
  CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(result));
  encoder.Put(digest, sizeof(digest));
  encoder.MessageEnd();

  return result;
}

std::string generateRandomKey(int keySize)
{
  CryptoPP::AutoSeededRandomPool rng;
  CryptoPP::SecByteBlock key(keySize);
  rng.GenerateBlock(key, keySize);

  std::string encodedKey;
  CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(encodedKey));
  encoder.Put(key.data(), key.size());
  encoder.MessageEnd();

  return encodedKey;
}

std::string readFileToString(const std::string &filename)
{
  std::ifstream file(filename);
  if (!file)
  {
    std::cerr << "Failed to open file: " << filename << std::endl;
    return "";
  }

  std::ostringstream oss;
  oss << file.rdbuf();
  return oss.str();
}

void save_key_dig(const std::string& save_path,const uint8_t *key,int key_len,const uint8_t *dig,int dig_len) {
    std::ofstream outfile(save_path, std::ios::trunc);
    if (outfile.is_open()) {
        outfile.write(reinterpret_cast<const char*>(key), key_len);
        // outfile.write(reinterpret_cast<const char*>(dig), dig_len);
        outfile.close();
    }
    else {
        std::cerr << "Unable to open file for writing." << std::endl;
    }
}

std::string Hash2(const std::string &filename, const std::string &key){
  using namespace CryptoPP;
  long long unsigned sum = 0;
  uint8_t *buffer = new uint8_t[BUFFER_SIZE];
  //unsigned long long *p = (unsigned long long *)&file_str[0];
  size_t count = 0;
  char* p_buffer = (char*) buffer;
  uint8_t *box = NULL;
  block *key_list = (block *)buffer;
  int key_list_size = BUFFER_SIZE / BLOCK_SIZE;
  std::ifstream file(filename, std::ios::binary);
  CryptoPP::Salsa20::Encryption enc;
  uint8_t iv[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  enc.SetKeyWithIV((uint8_t*)key.data(), 16, iv, 8);
  uint8_t input[BUFFER_SIZE]{};
  memset(input, 0, BUFFER_SIZE);
  unsigned long long *num1 = (unsigned long long*) buffer;
  unsigned long long *ecoff = (unsigned long long*) input;
  enc.ProcessData(input, input, BUFFER_SIZE);
  if (file) {
      while (file.read(p_buffer, BUFFER_SIZE)) {
          enc.ProcessData(input, input, BUFFER_SIZE);
          for (int i = 0; i < BUFFER_SIZE/(BLOCK_SIZE*2); ++i) {
              sum += num1[i]*ecoff[i];
          }
      }
      enc.ProcessData(input, input, BUFFER_SIZE);
      std::streamsize bytesRead = file.gcount();
      memset(buffer+bytesRead,0,BUFFER_SIZE-bytesRead);
      int rest = bytesRead/(BLOCK_SIZE*2);
      if(bytesRead%(BLOCK_SIZE*2)!=0){
        rest++;
      }
      for (int i = 0; i < rest; ++i) {
          sum += num1[i]*ecoff[i];
      }
      // std::cout<<"sum is "<<sum<<std::endl;
      return std::to_string(sum);
      file.close();
  } else {
      std::cout << "Failed to open the file." << std::endl;
  }
}
