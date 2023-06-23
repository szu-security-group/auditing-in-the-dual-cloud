#include "Server.h"
#include "general.h"
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <filesystem>
#include "timer.h"
#include "rc4.h"

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
        //timer t_time = timer();
        //t_time.set_start();
        sample_hash(file_str, key, digest);
        //indexless_hash(file_str, key, digest);
        //t_time.set_end();
        //t_time.compute_duration();
        //t_time.print_time_cost();
    }
    catch (std::ifstream::failure e)
    {
        std::cout << "ERROR::SHADER::FILE_NOT_SUCCESFULLY_READ" << std::endl;
    }
}



///****************************************************************************                 
/// @brief   : generate proof using the sampling file blocks
/// key      : generate random numbers as coefficients
/// index    : generate random indices                                                               
///****************************************************************************
void Server::sample_prove(uint8_t key[16], uint8_t index[16], uint8_t* digest)
{

    std::ifstream infile(file_path, std::ios::in | std::ios::binary);
    try {
        std::stringstream  file_str_stream;
        unsigned long long _file_size = std::filesystem::file_size(file_path);
        unsigned long long _blocks = floor(_file_size/BLOCK_SIZE);
        uint8_t* buffer = new uint8_t[BUFFER_SIZE];
        rc4 rc4_ = rc4(key, KEY_SIZE);
        int i = 0;
        uint32_t* index_list = new uint32_t[CHALLENGE_NUM];
        while (i<CHALLENGE_NUM) {
            rc4_.rc4keystream(buffer, BUFFER_SIZE);
            uint32_t* tmp_num = (uint32_t*)buffer;// tmp_number from 0 to 2^32-1
            for (int j = 0; j<BUFFER_SIZE/sizeof(uint32_t);j++) {
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
        //timer t_time = timer();
        //t_time.set_start();
        sample_hash(file_str, key, digest);
        indexless_hash(file_str, key, digest);
        //t_time.set_end();
        //t_time.compute_duration();
        //std::cout << "digest";
        //t_time.print_time_cost();
    }
    catch (std::ifstream::failure e)
    {
        std::cout << "ERROR::SHADER::FILE_NOT_SUCCESFULLY_READ" << std::endl;
    }
}
