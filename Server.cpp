#include "Server.h"
#include "general.h"
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <filesystem>
#include <openssl/sha.h>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/filters.h>
#include <cmath>
#include "timer.h"
#include "rc4.h"

timer s_prove_time = timer("s_prove");
timer s_prove_time1 = timer("s_prove_1");

Server::Server(std::string name) {
    name.copy(this->name, name.length());
};

///****************************************************************************                 
/// @brief   : generate proof using the whole file 
/// key      : generate random numbers as coefficients                                                           
///****************************************************************************
void Server::prove(const uint8_t *key, uint8_t* digest)
{
    std::ifstream infile(file_path, std::ios::in | std::ios::binary);
    try {
        std::stringstream  file_str_stream;
        file_str_stream << infile.rdbuf();
        infile.close();
        //padding zero
        unsigned long long _file_size = std::filesystem::file_size(file_path);
        int padding_length = sizeof(block) - _file_size % sizeof(block);
        file_str_stream << std::setfill((char)0) << std::setw(padding_length) << (char)0;
        std::string file_str = file_str_stream.str();
        s_prove_time1.set_start();
        indexless_hash(file_str, key, digest);
        s_prove_time1.set_end();

    }
    catch (std::ifstream::failure& e)
    {
        std::cout << "ERROR::SHADER::FILE_NOT_SUCCESFULLY_READ" << std::endl;
    }
}



///****************************************************************************                 
/// @brief   : generate proof using the sampling file blocks
/// key      : key for generating random numbers as coefficients
/// index    : key for generating random indices                                                               
///****************************************************************************
std::string Server::sample_prove(std::string key, std::string index_key)
{

    std::ifstream infile(file_path, std::ios::in | std::ios::binary);
    try {
        std::stringstream  file_str_stream;
        unsigned long long _file_size = std::filesystem::file_size(file_path);
        unsigned long long _blocks = std::floor((_file_size / BLOCK_SIZE));
        uint8_t* buffer = new uint8_t[BUFFER_SIZE];

        rc4 rc4_ = rc4((uint8_t*)index_key.data(), KEY_SIZE);
        int i = 0;
        // int CHALLENGE_NUM = get_challenge_num(_file_size / 4, 0.99, 0.01);
        int CHALLENGE_NUM = 460;
        uint32_t* index_list = new uint32_t[CHALLENGE_NUM];
        while (i<CHALLENGE_NUM) {
            rc4_.rc4keystream(buffer, BUFFER_SIZE);
            uint32_t* tmp_num = (uint32_t*)buffer;// tmp_number from 0 to 2^32-1
            for (unsigned long long j = 0; j<BUFFER_SIZE/sizeof(uint32_t);j++) {
                index_list[i]= *(tmp_num++)%_blocks;
                i++;
                if (i == CHALLENGE_NUM)
                    break;
            }
        }
        for (int i = 0; i < CHALLENGE_NUM; i++) {
            uint8_t block[BLOCK_SIZE];
            infile.seekg(index_list[i]*BLOCK_SIZE);
            infile.read((char*)block, BLOCK_SIZE);
            file_str_stream << std::string((char*)block, BLOCK_SIZE);
        }
        infile.close();
        //add length
        //for (int i = 0; i < 8; i++) {
        //    file_str_stream << (char) * ((char*)&_file_size + i);
        //}
        std::string file_str = file_str_stream.str();
        s_prove_time.set_start();
        uint8_t* digest = new uint8_t[BLOCK_SIZE];
        inner_hash(file_str, (uint8_t*)key.data(), digest);
        s_prove_time.set_end();
        std::string digest_s((char*) digest);
        return digest_s;
        //t_time.compute_duration();
    }
    catch (std::ifstream::failure& e)
    {
        std::cout << "ERROR::SHADER::FILE_NOT_SUCCESFULLY_READ" << std::endl;
        return "";
    }
}


std::string Server::daily_prove(uint8_t key[16], uint8_t index[16])
{

    std::ifstream infile(file_path, std::ios::in | std::ios::binary);
    try {
        std::stringstream  file_str_stream;
        unsigned long long _file_size = std::filesystem::file_size(file_path);
        unsigned long long _blocks = std::floor((_file_size / BLOCK_SIZE));
        uint8_t* buffer = new uint8_t[BUFFER_SIZE];
        rc4 rc4_ = rc4(key, KEY_SIZE);
        int i = 0;
        // int CHALLENGE_NUM = get_challenge_num(_file_size / 4, 0.99, 0.01);
        int CHALLENGE_NUM = 468;
        uint32_t* index_list = new uint32_t[CHALLENGE_NUM];
        while (i<CHALLENGE_NUM) {
            rc4_.rc4keystream(buffer, BUFFER_SIZE);
            uint32_t* tmp_num = (uint32_t*)buffer;// tmp_number from 0 to 2^32-1
            for (unsigned long long j = 0; j<BUFFER_SIZE/sizeof(uint32_t);j++) {
                index_list[i]= *(tmp_num++)%_blocks;
                i++;
                if (i == CHALLENGE_NUM)
                    break;
            }
        }
        for (int i = 0; i < CHALLENGE_NUM; i++) {
            uint8_t block[BLOCK_SIZE];
            infile.seekg(index_list[i]*BLOCK_SIZE);
            infile.read((char*)block, BLOCK_SIZE);
            file_str_stream << std::string((char*)block, BLOCK_SIZE);
        }
        infile.close();
        //add length
        //for (int i = 0; i < 8; i++) {
        //    file_str_stream << (char) * ((char*)&_file_size + i);
        //}
        unsigned char sha1digest[SHA_DIGEST_LENGTH];
        uint8_t* digest = new uint8_t[BLOCK_SIZE];
        std::string file_str = file_str_stream.str();
        std::string key_str(reinterpret_cast<const char*>(key),16);


        CryptoPP::SHA1 sha1;
        std::string hash;


        s_prove_time.set_start();
        //inner_hash(file_str, key, digest);
        inner_hash(file_str,key);
        //hmacSha1(key_str,file_str);
        //CryptoPP::HashFilter filter(sha1, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hash)));
        //CryptoPP::StringSource(file_str, true, new CryptoPP::Redirector(filter));

        //SHA1(reinterpret_cast<const unsigned char*>(file_str.c_str()), file_str.length(), sha1digest);//openssl
        // std::cout<<sha1digest<<std::endl;
        s_prove_time.set_end();
        std::string digest_s((char*) digest);
        return digest_s;
        //t_time.compute_duration();
    }
    catch (std::ifstream::failure& e)
    {
        std::cout << "ERROR::SHADER::FILE_NOT_SUCCESFULLY_READ" << std::endl;
        return "";
    }
}
