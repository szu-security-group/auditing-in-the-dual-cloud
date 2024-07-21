#include <iostream>
#include <fstream>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/osrng.h>
#include <cryptopp/files.h>
#include <random>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include "general.h"
#include "rijndael.h"
#include "timer.h"


timer c_modify_timer = timer("modify");
timer c_insert_timer = timer("insert");
timer c_delete_timer = timer("delete");


void modifyData(const std::string& filePath,unsigned int index,const uint8_t *data,int data_len,
        const uint8_t *key,int key_len,const uint8_t *dig,int dig_len){
    std::ifstream file(filePath, std::ios::binary);
    uint8_t input_block[AES_BLOCK_SIZE],output_block[AES_BLOCK_SIZE];
    if (!file.is_open()) {
        std::cerr << "Failed to open file." << std::endl;
        return;
    }
    char originalData[20];
    file.seekg((index-2)*BLOCK_SIZE,std::ios::beg);
    file.read(originalData,5*BLOCK_SIZE);
    AES_KEY aesKey;
    AES_set_encrypt_key(key, 128, &aesKey);
    unsigned int *pr = (unsigned int *)(originalData);
    unsigned int *coeff = (unsigned int *)output_block;
    unsigned long long int sum = *((unsigned*)dig);
    for(unsigned int i=0;i<3;i++){
        memset(input_block, 0, BLOCK_SIZE * 4);
        memcpy(input_block, pr, BLOCK_SIZE * 3);
        AES_encrypt(input_block, output_block, &aesKey);
        sum = sum - *pr *(*coeff);
        pr++;
    }
    // modify data
    for(unsigned int i=0;i<BLOCK_SIZE;i++){
        originalData[i+2*BLOCK_SIZE]=data[i];
    }
    pr = (unsigned int *)(originalData);
    for(unsigned int i=0;i<3;i++){
        memset(input_block, 0, BLOCK_SIZE * 4);
        memcpy(input_block, pr, BLOCK_SIZE * 3);
        AES_encrypt(input_block, output_block, &aesKey);
        sum = sum + *pr *(*coeff);
        pr++;
    }
}



void deleteData(const std::string& filePath,unsigned int index,
        const uint8_t *key,int key_len,const uint8_t *dig,int dig_len){
    std::ifstream file(filePath, std::ios::binary);
    uint8_t input_block[AES_BLOCK_SIZE],output_block[AES_BLOCK_SIZE];
    if (!file.is_open()) {
        std::cerr << "Failed to open file." << std::endl;
        return;
    }
    char originalData[20];
    char lastData[16];
    file.seekg((index-2)*BLOCK_SIZE,std::ios::beg);
    file.read(originalData,5*BLOCK_SIZE);
    AES_KEY aesKey;
    AES_set_encrypt_key(key, 128, &aesKey);
    unsigned int *pr = (unsigned int *)(originalData);
    unsigned int *coeff = (unsigned int *)output_block;
    unsigned long long int sum = *((unsigned*)dig);
    for(unsigned int i=0;i<3;i++){
        memset(input_block, 0, BLOCK_SIZE);
        memcpy(input_block, pr, BLOCK_SIZE * 3);
        AES_encrypt(input_block, output_block, &aesKey);
        sum = sum - *pr *(*coeff);
        pr++;
    }
    // delete data, move 2 last blcok forward
    for(unsigned int i=0;i<BLOCK_SIZE*2;i++){
        originalData[i+2*BLOCK_SIZE]=originalData[i+3*BLOCK_SIZE];
    }
    pr = (unsigned int *)(originalData);
    for(unsigned int i=0;i<2;i++){
        memset(input_block, 0, BLOCK_SIZE);
        memcpy(input_block, pr, BLOCK_SIZE * 3);
        AES_encrypt(input_block, output_block, &aesKey);
        sum = sum + *pr *(*coeff);
        pr++;
    }
    file.seekg(0, std::ios::end);
    unsigned int fileSize = file.tellg();
    file.seekg(fileSize-8);
    file.read(lastData,8);
    memcpy(lastData+8,(char*)&fileSize,8);
    pr = (unsigned int *)(lastData);
    for(unsigned int i=0;i<2;i++){
        memset(input_block, 0, BLOCK_SIZE * 4);
        memcpy(input_block, pr, BLOCK_SIZE * 3);
        AES_encrypt(input_block, output_block, &aesKey);
        sum = sum - *pr *(*coeff);
        pr++;
    }
    fileSize = fileSize-8;
    memcpy(lastData+8,(char*)&fileSize,8);
    pr = (unsigned int *)(lastData);
    for(unsigned int i=0;i<2;i++){
        memset(input_block, 0, BLOCK_SIZE * 4);
        memcpy(input_block, pr, BLOCK_SIZE * 3);
        AES_encrypt(input_block, output_block, &aesKey);
        sum = sum + *pr *(*coeff);
        pr++;
    }
}

void insertData(const std::string& filePath,unsigned int index,const uint8_t *data,int data_len,
        const uint8_t *key,int key_len,const uint8_t *dig,int dig_len){
    std::ifstream file(filePath, std::ios::binary);
    uint8_t input_block[AES_BLOCK_SIZE],output_block[AES_BLOCK_SIZE];
    if (!file.is_open()) {
        std::cerr << "Failed to open file." << std::endl;
        return;
    }
    char originalData[5*BLOCK_SIZE];
    char lastData[4*BLOCK_SIZE];
    file.seekg((index-2)*BLOCK_SIZE,std::ios::beg);
    file.read(originalData,4*BLOCK_SIZE);
    AES_KEY aesKey;
    AES_set_encrypt_key(key, 128, &aesKey);
    unsigned int *pr = (unsigned int *)(originalData);
    unsigned int *coeff = (unsigned int *)output_block;
    unsigned long long int sum = *((unsigned*)dig);
    for(unsigned int i=0;i<2;i++){
        memset(input_block, 0, BLOCK_SIZE);
        memcpy(input_block, pr, BLOCK_SIZE * 3);
        AES_encrypt(input_block, output_block, &aesKey);
        sum = sum - *pr *(*coeff);
        pr++;
    }
    // move 2 last blcok back
    for(unsigned int i=0;i<BLOCK_SIZE*2;i++){
        originalData[5*BLOCK_SIZE-i-1]=originalData[3*BLOCK_SIZE-i-1];
    }
    // insert data
    for(unsigned int i=0;i<BLOCK_SIZE;i++){
        originalData[2*BLOCK_SIZE+i]=data[i];
    }
    pr = (unsigned int *)(originalData);
    for(unsigned int i=0;i<3;i++){
        memset(input_block, 0, BLOCK_SIZE);
        memcpy(input_block, pr, BLOCK_SIZE * 3);
        AES_encrypt(input_block, output_block, &aesKey);
        sum = sum + *pr *(*coeff);
        pr++;
    }


    file.seekg(0, std::ios::end);
    unsigned int fileSize = file.tellg();
    file.seekg(fileSize-8);
    file.read(lastData,8);
    memcpy(lastData+8,(char*)&fileSize,8);
    pr = (unsigned int *)(lastData);
    for(unsigned int i=0;i<2;i++){
        memset(input_block, 0, BLOCK_SIZE * 4);
        memcpy(input_block, pr, BLOCK_SIZE * 3);
        AES_encrypt(input_block, output_block, &aesKey);
        sum = sum - *pr *(*coeff);
        pr++;
    }
    fileSize = fileSize+8;
    memcpy(lastData+8,(char*)&fileSize,8);
    pr = (unsigned int *)(lastData);
    for(unsigned int i=0;i<2;i++){
        memset(input_block, 0, BLOCK_SIZE * 4);
        memcpy(input_block, pr, BLOCK_SIZE * 3);
        AES_encrypt(input_block, output_block, &aesKey);
        sum = sum + *pr *(*coeff);
        pr++;
    }
}

void testUpdate(std::string file_path){
    std::ifstream file(file_path);

    if (!file.is_open()) {
        std::cerr << "Failed to create file." << std::endl;
        return;
    }
    file.seekg(0, std::ios::end);
    std::streampos fileSize = file.tellg();  
    int minV = 2;
    int maxV = fileSize/BLOCK_SIZE-2;
    std::random_device rd;  
    std::mt19937 generator(rd());  
    std::uniform_int_distribution<int> distribution(minV, maxV);
    int test_num = 10000, index = 0;
    std::string randomBytes;
    randomBytes.resize(BLOCK_SIZE);
    std::string key_dig_path = "../data/key_dig.txt";
    std::ifstream infile(key_dig_path, std::ios::binary);
    unsigned char key[16];
    unsigned char dig[8];
    if (infile.is_open()) {
        infile.read(reinterpret_cast<char*>(key), sizeof(key));
        infile.read(reinterpret_cast<char*>(dig), sizeof(dig));
        infile.close();
    }

    for (int i = 0; i < test_num; ++i) {
        // index = distribution(generator);
        index = 256+i;
        RAND_bytes(reinterpret_cast<unsigned char*>(&randomBytes[0]), randomBytes.size());
        // std::cout<<"index :"<<index<<""<<std::endl;
        c_modify_timer.set_start();
        //modifyData(file_path,index,(uint8_t*)randomBytes.data(),8,key,16,dig,8);
        deleteData(file_path,index,key,16,dig,8);
        //insertData(file_path,index,(uint8_t*)randomBytes.data(),8,key,16,dig,8);
        c_modify_timer.set_end();
    }
    c_modify_timer.cal_average_duration(Nanoseconds);

}
