#include "rijndael.h"
#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
#include "general.h"

rijndael::rijndael(__m128i key)
{
	setKey(key);
}

rijndael::rijndael(const uint8_t* key)
{
	__m128i tmp = _mm_loadu_si128((__m128i*)key);
	setKey(tmp);
}

void rijndael::setKey(__m128i key)
{
	this->user_key = key;
	key_expansion();
}

void rijndael::key_expansion()
{
	this->nr = 10;
	__m128i temp1, temp2;
	__m128i* Key_Schedule = this->expand_encrypt_key;
	int KS_Pointer = 1;
	temp1 = _mm_loadu_si128(&this->user_key);
	Key_Schedule[0] = temp1;
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x1);
	key_expansion_128(&temp1, &temp2, KS_Pointer++);
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x2);
	key_expansion_128(&temp1, &temp2, KS_Pointer++);
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x4);
	key_expansion_128(&temp1, &temp2, KS_Pointer++);
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x8);
	key_expansion_128(&temp1, &temp2, KS_Pointer++);
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x10);
	key_expansion_128(&temp1, &temp2, KS_Pointer++);
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x20);
	key_expansion_128(&temp1, &temp2, KS_Pointer++);
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x40);
	key_expansion_128(&temp1, &temp2, KS_Pointer++);
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x80);
	key_expansion_128(&temp1, &temp2, KS_Pointer++);
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x1b);
	key_expansion_128(&temp1, &temp2, KS_Pointer++);
	temp2 = _mm_aeskeygenassist_si128(temp1, 0x36);
	key_expansion_128(&temp1, &temp2, KS_Pointer++);
}

void rijndael::key_expansion_128(__m128i* tmp1, __m128i* tmp2, int Pointer)
{
	__m128i tmp3;
	*tmp2 = _mm_shuffle_epi32(*tmp2, 0xff);
	tmp3 = _mm_slli_si128(*tmp1, 0x4);
	*tmp1 = _mm_xor_si128(*tmp1, tmp3);
	tmp3 = _mm_slli_si128(tmp3, 0x4);
	*tmp1 = _mm_xor_si128(*tmp1, tmp3);
	tmp3 = _mm_slli_si128(tmp3, 0x4);
	*tmp1 = _mm_xor_si128(*tmp1, tmp3);
	*tmp1 = _mm_xor_si128(*tmp1, *tmp2);
	this->expand_encrypt_key[Pointer] = *tmp1;
}

void rijndael::encrypt(const uint8_t* input, uint8_t* output)
{
	__m128i tmp1;
	int j;
	tmp1 = _mm_shuffle_epi8(*(__m128i*)input, BSWAP_EPI64);
	tmp1 = _mm_xor_si128(tmp1, this->expand_encrypt_key[0]);
	for (j = 1; j < this->nr - 1; j+=2) {
		tmp1 = _mm_aesenc_si128(tmp1,this->expand_encrypt_key[j]);
		tmp1 = _mm_aesenc_si128(tmp1, this->expand_encrypt_key[j + 1]);
	}
	tmp1 = _mm_aesenc_si128(tmp1, this->expand_encrypt_key[nr - 1]);
	tmp1 = _mm_aesenclast_si128(tmp1, this->expand_encrypt_key[nr]);
	*(__m128i*)output = tmp1;
}

void test_rijndael()
{
	__m128i key;
	uint8_t output[16]{};
	uint8_t input[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t tmp2[16] = { 0xca, 0xea, 0x65, 0xcd, 0xbb, 0x75, 0xe9, 0x16, 0x9e, 0xcd, 0x22, 0xeb, 0xe6, 0xe5, 0x46, 0x75 };
	key = _mm_loadu_si128((__m128i*)tmp2);
	rijndael cipher = rijndael(key);
	cipher.encrypt(input, output);
	print_bytes(output, 16);
}
