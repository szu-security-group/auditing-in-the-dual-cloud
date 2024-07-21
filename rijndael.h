#pragma once
#include <stdint.h>
#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>

class rijndael
{
public:
	__m128i user_key;
	__m128i expand_encrypt_key[15];
	__m128i BSWAP_EPI64 = _mm_set_epi8(8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5,
		6, 7);
	int nr = 10;
	rijndael(__m128i key);
	rijndael(const uint8_t* key);
	void setKey(__m128i key);
	void key_expansion();
	void key_expansion_128(__m128i* tmp1, __m128i* tmp2, int Pointer);
	void encrypt(const uint8_t* input, uint8_t* output);
};

void test_rijndael();