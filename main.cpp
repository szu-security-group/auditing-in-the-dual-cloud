#include "timer.h"
#include "Client.h"
#include "general.h"
#include "Server.h"
#include "gfmul.h"
#include "salsa20.h"
#include <string>
#include <sstream>
#include <iostream>
#include <cryptopp/sha.h>
#include <cryptopp/hex.h>
#include <cryptopp/hmac.h>
#include <cryptopp/filters.h>
#include <openssl/sha.h>
#include <vector>
#include "update.h"


/*
std::string sha256(const std::string& data) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), digest);

    char hexDigest[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        sprintf(hexDigest + (i * 2), "%02x", digest[i]);
    }

    return std::string(hexDigest);
}
int main() {
    std::string data = "your_data";

    std::string hash = sha256(data);
    std::cout << "SHA256 Hash: " << hash << std::endl;

    return 0;
}*/

using namespace std;

extern timer c_audit_time;
extern timer c_verify_time;
extern timer c_keygen_time;
extern timer s_prove_time;
extern timer s_prove_time1;
extern timer hash2_time;;


// int main() {
// 	unsigned int a = get_challenge_num(2621440,0.99,0.01);
// 	cout << a << endl;
// 	return 0;
// }

using namespace std;

// int main(){
// 	int keySize = 32;
// 	std::string randomKey = generateRandomKey(keySize);
// 	timer hash_cost = timer("hash_cost");
// 	// vector<string> data_set = {"../data/1MB","../data/2MB","../data/4MB","../data/8MB","../data/16MB","../data/32MB","../data/64MB","../data/128MB"};
// 	// for(const string&m_str:data_set){
// 		// std::ifstream file(m_str);
// 		// std::stringstream buffer;
// 		// buffer << file.rdbuf();
// 		// file.close();
// 		// string content = buffer.str();
// 		// CryptoPP::SHA1 sha1;
// 		// CryptoPP::SHA256 sha256;
// 		// std::string hash;
// 		for(int i=0;i<4;i++){
// 			hash_cost.set_start();
// 			// hmacSha256(randomKey, buffer.str());
// 			//hmacSha1(randomKey, buffer.str());
// 			// calculateHmacSha1("../data/10GB", randomKey);
// 			// inner_hash(content,(uint8_t*)randomKey.data());
// 			// func11(i);
// 			// cout<<i<<endl;
// 			// hmacSha1(randomKey,buffer.str());
// 			// CryptoPP::StringSource(buffer.str(), true, new CryptoPP::HashFilter(sha1, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hash))));
// 			// CryptoPP::StringSource(buffer.str(), true, new CryptoPP::HashFilter(sha1, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hash))));
// 			//CryptoPP::StringSource(buffer.str(), true, new CryptoPP::HashFilter(sha256, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hash))));
// 			hash_cost.set_end();
// 		}
// 		hash_cost.cal_average_duration(Nanoseconds);
// 		hash_cost.clear();
// 	// }
	
// }

// compare hash funciton
/*
int main(){
	int keySize = 16; // 密钥字节大小
	timer hash256 = timer("hash");
    std::string randomKey = generateRandomKey(keySize);	
	// std::string message = readFileToString("../data/1GB");
	std::string hmacSha256Hash1;
	std::string hmacSha256Hash2;
	for(int i=0;i<4;i++){
		hash256.set_start();
		// hmacSha256Hash1 = hmacSha256(randomKey, message);
		//hmacSha256Hash2 = calculateHmacSha1("../data/2GB", randomKey);
		Hash1("../data/5GB",randomKey);
		hash256.set_end();
	}
	hash256.cal_average_duration(Nanoseconds);
	// cout<<hmacSha256Hash1<<endl;
	//cout<<hmacSha256Hash2<<endl;
}
*/


/*
int main(){
	testUpdate("../data/100MB");
	return 0;
}*/

/*
int main(){
	alignas(16) char data[12] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C };
	__m128i xmm = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data));
	alignas(4) char data1[4] = {0x11, 0x23, 0x34, 0x45};
	int32_t* value = (int32_t*)data1;
	xmm = _mm_bsrli_si128(xmm, 4);
	xmm = _mm_insert_epi32(xmm,*value,2);
	print_bytes((const uint8_t*)&xmm,16);
}
*/


int main() {
	Server serverA = Server("ServerA");
	// uint8_t* proofA = new uint8_t[BLOCK_SIZE];
	std::string proofA;
	std::string proofA_str;
	Client client = Client("client");
	// Server serverB = Server("ServerB");
	// uint8_t* proofB = new uint8_t[BLOCK_SIZE];
	uint8_t* key =  new uint8_t[KEY_SIZE];
	uint8_t* index_key = new uint8_t[KEY_SIZE];
	client.KeyGen();
	c_keygen_time.cal_average_duration(Nanoseconds);
	//c_audit_time.cal_average_duration(Nanoseconds);
	// for(int i=0;i<50;i++){
	// client.Audit(key,index_key);
	// }
	// c_audit_time.cal_average_duration(Nanoseconds);
	// std::string s_key((char*)key,KEY_SIZE);
	// std::string s_index_key((char*)index_key,KEY_SIZE);
	// for (int i = 0; i < 50; i++) {
	// 	// proofA = serverA.sample_prove(s_key, s_index_key);
	// 	proofA_str = serverA.daily_prove(key, index_key);
	// 	cout<<proofA<<endl;
	// }
	// s_prove_time.cal_average_duration(Nanoseconds);
	// hash2_time.cal_average_duration(Nanoseconds);
	
	// serverB.sample_prove(key, index_key, proofB);
	//set query to Server
	//print_bytes(proofA, 8);
	//print_bytes(proofB, 8);
	////if audit pass
	// bool *result=NULL;
	// if (client.Verify(proofA, proofB)) {
	// 	result = new bool[2];
	// 	if (result != NULL) {
	// 		result[0] = true;
	// 		result[1] = true;
	// 	}
	// 	delete[]result;
	// }
	
	//c_verify_time.cal_average_duration(Nanoseconds);
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

	//delete []proofA;
	//delete []proofB;
	//delete[]key;
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

/*
#include <cryptopp/cryptlib.h>
#include <cryptopp/sha.h>
#include <iostream>
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

/*
#include <cryptopp/cryptlib.h>
#include <cryptopp/gcm.h>
#include <cryptopp/osrng.h>
#include <cryptopp/hex.h>
#include <cryptopp/hmac.h>
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
