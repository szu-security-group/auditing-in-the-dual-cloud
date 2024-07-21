#pragma once
#include "general.h"
#include "timer.h"
#include <fstream>
#include <string>
class Server
{
public:
	void prove(const uint8_t *Key,uint8_t* digest);
	std::string sample_prove(std::string key, std::string index_key);
	std::string daily_prove(uint8_t key[16], uint8_t index[16]);
	char name[20];
	Server(std::string name);
};

extern timer s_prove_time;
extern timer s_prove_time1;
