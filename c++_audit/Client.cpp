#include "Client.h"
#include "general.h"
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <filesystem>
#include <crypto870/osrng.h>
#include "timer.h"

///****************************************************************************                                                               
/// @input   :digestA digest from ServerA ,digestB digest from ServerB                                                                  
/// @output  :                                                                 
/// @brief   :generate some keys and Corresponding digests with hash fuction ,which supports dynamic update                                                               
///****************************************************************************
void Client::KeyGen()
{
	std::ifstream infile(file_path, std::ios::in | std::ios::binary);
	std::stringstream  file_str_stream;
	char buffer[BUFFER_SIZE]{};
	uint8_t local_digest[AES_BLOCK_SIZE]{};
	unsigned long long _file_size = std::filesystem::file_size(file_path);
	int padding_length = AES_BLOCK_SIZE - _file_size % AES_BLOCK_SIZE;
	file_str_stream << infile.rdbuf();
	file_str_stream << std::setfill((char)0) << std::setw(padding_length) << (char)0;
	std::string file_str = file_str_stream.str();
	//timer t_time = timer();
	//t_time.set_start();
	for (auto i = 0; i < DIGEST_SIZE; i++) {
		CryptoPP::SecByteBlock block(CryptoPP::AES::DEFAULT_KEYLENGTH);
		CryptoPP::OS_GenerateRandomBlock(false, block, block.size());
		indexless_hash(file_str, block.BytePtr(), local_digest);
		// get the local keys and digests and store them
	}
	//t_time.set_end();
	//t_time.compute_duration();
	//t_time.print_time_cost();
}

uint8_t* Client::Aduit()
{
	// randomly generate key with openssl/crypto++ 
	// like uint8_t key[16] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08 };
	//timer t_time = timer();
	//t_time.set_start();
	uint8_t* key = new uint8_t[16];
	CryptoPP::SecByteBlock block(CryptoPP::AES::DEFAULT_KEYLENGTH);
	CryptoPP::OS_GenerateRandomBlock(true,block,block.size());
	//t_time.set_end();
	//t_time.compute_duration();
	//t_time.print_time_cost();
	for (auto i = 0; i < block.size();i++) {
		key[i]=block[i];
	}
	return key;
}

Client::Client(std::string name)
{
	name.copy(this->name, name.length());
}

bool Client::Verify(uint8_t* digestA, uint8_t* digestB)
{
	//timer time1 = timer();
	//time1.set_start();
	uint8_t tmp[BLOCK_SIZE]{};
	uint64_t* p = (uint64_t*)tmp;
	for (int i = 0; i < BLOCK_SIZE; i++)
		tmp[i] = digestA[i] ^ digestB[i];
	//time1.set_end();
	//time1.compute_duration();
	//time1.print_time_cost();
	if (*p == 0)
		return true;
	else
		return false;
}

bool* Client::localVerify(uint8_t* digestA, uint8_t* digestB, uint8_t* local_digest)
{
	bool* result = new bool[2];
	uint8_t tmp1[AES_BLOCK_SIZE]{}, tmp2[AES_BLOCK_SIZE]{};
	unsigned long long* p1 = (unsigned long long*)tmp1;
	unsigned long long* p2 = (unsigned long long*)tmp2;
	for (int i = 0; i < AES_BLOCK_SIZE; i++) {
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

