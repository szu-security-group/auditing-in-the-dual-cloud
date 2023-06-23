#pragma once
#include "general.h"
class Client
{
public:
	char name[20];
	void KeyGen();
	uint8_t* Aduit();
	Client(std::string name);
	bool Verify(uint8_t* digestA, uint8_t* digestB);
	bool* localVerify(uint8_t* digestA, uint8_t* digestB, uint8_t* localdigest);
};

