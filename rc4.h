#pragma once
#include <stdint.h>
class rc4
{
private:
	int box_i = 0,box_j = 0;
	uint8_t box[256];
	uint8_t k[256];
public:
	rc4(const uint8_t *key, int key_length);
	void rc4keystream(uint8_t* stream, unsigned long long int length);
	void rc4decrypt(uint8_t* plaintext,uint8_t* ciphertext,unsigned long long int key_length);
};

