#include "Client.h"
#include "general.h"
#include "timer.h"
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <filesystem>
#include <cryptopp/osrng.h>


timer c_keygen_time = timer("keygen");
timer c_audit_time = timer("audit");
timer c_verify_time = timer("verify");

using namespace std;

///****************************************************************************                                                               
/// @input   :digestA digest from ServerA ,digestB digest from ServerB                                                                  
/// @output  :                                                                 
/// @brief   :generate some keys and Corresponding digests with hash fuction ,which supports dynamic update                                                               
///****************************************************************************
void Client::KeyGen()
{
	// std::ifstream infile(file_path, std::ios::in | std::ios::binary);
	// std::stringstream  file_str_stream;
	// uint8_t local_digest[BLOCK_SIZE]{};
	// unsigned long long _file_size = std::filesystem::file_size(file_path);
	// int padding_length = BLOCK_SIZE - _file_size % BLOCK_SIZE;
	//uint8_t local_digest[AES_BLOCK_SIZE]{};
	//unsigned long long _file_size = std::filesystem::file_size(file_path);
	//int padding_length = AES_BLOCK_SIZE - _file_size % AES_BLOCK_SIZE;
	// file_str_stream << infile.rdbuf();
	// // padding stream to 0...01
	// if(padding_length!=BLOCK_SIZE)
	// 	file_str_stream << std::setfill((char)0) << std::setw(padding_length-1) << (char)1;
	// unsigned int re_size = (unsigned int)_file_size;
	// std::string file_str;
	// file_str_stream.write(reinterpret_cast<char*>(&re_size), sizeof(re_size));
	// file_str_stream.write(reinterpret_cast<char*>(&re_size), sizeof(re_size));
	// file_str = file_str_stream.str();
	// cout<<file_str.size()<<endl;
	c_keygen_time.set_start();
	for (auto i = 0; i < DIGEST_SIZE; i++) {
		CryptoPP::SecByteBlock block(CryptoPP::AES::DEFAULT_KEYLENGTH);
		CryptoPP::OS_GenerateRandomBlock(false, block, block.size());
		// Hash1_v1(file_str, block.BytePtr(), local_digest);
		hash1_v3(block.BytePtr());
		// get the local keys and digests and store them
		// std::cout << "generate " << i << " ready "<<std::endl;
	}
	c_keygen_time.set_end();
}

void Client::Audit(uint8_t*key,uint8_t*index_key)
{
	// randomly generate key with openssl/crypto++ 
	// like uint8_t key[16] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08 };
	c_audit_time.set_start();
	CryptoPP::SecByteBlock block(CryptoPP::AES::DEFAULT_KEYLENGTH);
	CryptoPP::OS_GenerateRandomBlock(true, block, block.size());
	memcpy(key, block, M_AES_BLOCK_SIZE);
	CryptoPP::OS_GenerateRandomBlock(true, block, block.size());
	memcpy(index_key, block, M_AES_BLOCK_SIZE);
	c_audit_time.set_end();
}

Client::Client(std::string name)
{
	name.copy(this->name, name.length());
}

bool Client::Verify(uint8_t* digestA, uint8_t* digestB)
{
	c_verify_time.set_start();
	uint8_t tmp[BLOCK_SIZE]{};
	uint64_t* p = (uint64_t*)tmp;
	for (int i = 0; i < BLOCK_SIZE; i++)
		tmp[i] = digestA[i] ^ digestB[i];
	c_verify_time.set_end();
	if (*p == 0)
		return true;
	else
		return false;
}

bool* Client::localVerify(uint8_t* digestA, uint8_t* digestB, uint8_t* local_digest)
{
	bool* result = new bool[2];
	uint8_t tmp1[M_AES_BLOCK_SIZE]{}, tmp2[M_AES_BLOCK_SIZE]{};
	unsigned long long* p1 = (unsigned long long*)tmp1;
	unsigned long long* p2 = (unsigned long long*)tmp2;
	for (int i = 0; i < M_AES_BLOCK_SIZE; i++) {
		tmp1[i] = digestA[i] ^ local_digest[i];
		tmp2[i] = digestB[i] ^ local_digest[i];
	}
	if (*p1 == 0 && *(p1 + 1) == 0) {
		result[0] = true;
	}
	else {
		result[0] = false;
	}
	if (*p2 == 0 && *(p2 + 1) == 0) {
		result[0] = true;
	}
	else {
		result[0] = false;
	}
	return result;
}

