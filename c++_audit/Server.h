#pragma once
#include "general.h"
#include <fstream>
class Server
{
public:
	void prove(const uint8_t *Key,uint8_t* digest);
	void sample_prove(uint8_t key[16],uint8_t index[16], uint8_t* digest);
	char name[20];
	Server(std::string name);
};

