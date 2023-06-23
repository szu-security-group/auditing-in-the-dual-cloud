#include "Client.h"
#include "general.h"
#include "Server.h"
#include "gfmul.h"
#include "salsa20.h"
#include <string>
#include <sstream>
#include <iostream>
#include "timer.h"




int main() {
	Server serverA = Server("ServerA");
	Server serverB = Server("ServerB");
	Client client = Client("client");
	uint8_t* proofA = new uint8_t[BLOCK_SIZE];
	uint8_t* proofB = new uint8_t[BLOCK_SIZE];
	uint8_t* key = NULL;
	bool *result=NULL;
	client.KeyGen();
	key = client.Aduit();
	uint8_t index_key[KEY_SIZE] = { 0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08 };
	//serverA.sample_prove(key, index_key, proofA);
	//serverB.sample_prove(key, index_key, proofB);
	//set query to Server
	serverA.prove(key, proofA);
	serverB.prove(key, proofB);
	//print_bytes(proofA, 8);
	//print_bytes(proofB, 8);
	////if audit pass
	if (client.Verify(proofA, proofB)){
		result = new bool[2];
		if (result != NULL) {
			result[0] = true;
			result[1] = true;
		}
		delete[]result;
	}
	//// extra audit to confirm demaged source
	//else {
	//	// you can use the local_key and digest in KenGen
	//	byte_t* local_digest=NULL;
	//	byte_t* local_key = NULL;
	//	//send local key to serverA and serverB
	//	proofA = serverA.prove(local_key);
	//	proofB = serverB.prove(local_key);
	//	result = client.localVerify(proofA, proofB, local_digest, 16);
	//}

	delete []proofA;
	delete []proofB;
	delete[]key;
	return 0;
}

/*
int main() {
	test_gfmul();
}
*/
/*
int main() {
	byte_t* box = NULL;
	byte_t key[16] = {0x59,0xf3,0x02,0xc3,0x25,0x9a,0x82,0x30,0x0b,0xbb,0x25,0x7f,0x7e,0x3b,0xd2,0xdc};
	byte_t* stream = NULL;
	int t1 = 0, t2 = 0;
	for (int i = 0; i < 4; i++) {
		stream = rc4stream(t1,t2,box,key,KEY_SIZE);
		//print_box(box);
		print_buffer(stream);
	}
}*/

/*
int main() {
	using namespace ucstk;
	uint8_t key_[KEY_SIZE]={ 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	uint8_t iv_[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	size_t IV_OFFSET = Salsa20::KEY_SIZE;
	Salsa20 salsa20(key_);
	salsa20.setIv(iv_);
	const auto chunkSize = NUM_OF_BLOCKS_PER_CHUNK * Salsa20::BLOCK_SIZE;
	uint8_t chunk[chunkSize]{};
	std::string inputFileName_ = file_path;
	std::ifstream inputStream(inputFileName_, std::ios_base::binary);
	std::stringstream outputStream;
	inputStream.seekg(0, std::ios_base::end);
	auto fileSize = inputStream.tellg();
	inputStream.seekg(0, std::ios_base::beg);
	auto numChunks = fileSize / chunkSize;
	auto remainderSize = fileSize % chunkSize;

	// process file
	for (decltype(numChunks) i = 0; i < numChunks; ++i)
	{
		inputStream.read(reinterpret_cast<char*>(chunk), sizeof(chunk));
		salsa20.processBlocks(chunk, chunk, NUM_OF_BLOCKS_PER_CHUNK);
		outputStream.write(reinterpret_cast<const char*>(chunk), sizeof(chunk));

		float percentage = 100.0f * static_cast<float>(i + 1) / static_cast<float>(numChunks);
		std::printf("[%3.2f]\r", percentage);
	}

	if (remainderSize != 0)
	{
		inputStream.read(reinterpret_cast<char*>(chunk), remainderSize);
		salsa20.processBytes(chunk, chunk, remainderSize);
		outputStream.write(reinterpret_cast<const char*>(chunk), remainderSize);
	}
	std::string hex_result = binaryToHex(outputStream.str());
	std::cout << hex_result << std::endl;
}
*/

/*
#include <wmmintrin.h>
#include <stdio.h>
#include "rijndael.h"
#include "general.h"

int main()
{
	test_rijndael();
	test_salsa20_stream();
}
*/

#include <crypto870/cryptlib.h>
#include <crypto870/sha.h>
#include <iostream>


/*
int main() {
	using namespace CryptoPP;
	std::ifstream infile(file_path, std::ios::in | std::ios::binary);
	std::stringstream  file_str_stream;
	file_str_stream << infile.rdbuf();
	std::string msg = file_str_stream.str();
	std::string digest;

	SHA1 hash;
	timer time1 = timer();
	time1.set_start();
	hash.Update((const byte*)msg.data(), msg.size());
	digest.resize(hash.DigestSize());
	hash.Final((byte*)&digest[0]);
	time1.set_end();
	time1.compute_duration();
	time1.print_time_cost();
	return 0;
}*/


#include <crypto870/cryptlib.h>
#include <crypto870/gcm.h>
#include <crypto870/osrng.h>
#include <crypto870/hex.h>
#include <crypto870/hmac.h>

/*
int main() {
	using namespace CryptoPP;
	using namespace std;
	AutoSeededRandomPool prng;

	SecByteBlock key(16);
	prng.GenerateBlock(key, key.size());
	CryptoPP::byte iv[AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));
	string cipher, encoded;
	const int TAG_SIZE = 12;
	ifstream infile(file_path, std::ios::in | std::ios::binary);
	stringstream  file_str_stream;
	file_str_stream << infile.rdbuf();
	string pdata = file_str_stream.str();



	timer time1 = timer();
	time1.set_start();
	GCM< AES >::Encryption e;
	e.SetKeyWithIV(key, key.size(), iv, sizeof(iv));

	StringSource ss1(pdata, true,
		new AuthenticatedEncryptionFilter(e,
			new StringSink(cipher), false, TAG_SIZE
		) // AuthenticatedEncryptionFilter
	); // StringSource
	
	time1.set_end();
	time1.compute_duration();
	time1.print_time_cost();

}
*/
