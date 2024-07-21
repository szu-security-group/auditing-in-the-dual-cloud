#pragma once
#include<string>

void modifyData(const std::string& filePath,unsigned int index,const uint8_t *data,int data_len,
        const uint8_t *key,int key_len,const uint8_t *dig,int dig_len);

void testUpdate(std::string file_path);

void deleteData(const std::string& filePath,unsigned int index,
        const uint8_t *key,int key_len,const uint8_t *dig,int dig_len);

void insertData(const std::string& filePath,unsigned int index,const uint8_t *data,int data_len,
        const uint8_t *key,int key_len,const uint8_t *dig,int dig_len);