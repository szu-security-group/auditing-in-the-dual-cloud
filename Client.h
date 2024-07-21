#pragma once
#include "general.h"
#include "timer.h"
class Client
{
public:
	char name[20];
	void KeyGen();
	void Audit(uint8_t* key, uint8_t* index_key);
	Client(std::string name);
	bool Verify(uint8_t* digestA, uint8_t* digestB);
	bool* localVerify(uint8_t* digestA, uint8_t* digestB, uint8_t* localdigest);
};

extern timer c_audit_time;
extern timer c_verify_time;
extern timer c_keygen_time;