#include "rc4.h"
#include <stdio.h>
#include "general.h"
#include <iostream>
#include <exception>



///****************************************************************************
/// @key          :                                                                 
/// @key_length   :                                                                 
/// @box          :                                                                 
/// @brief        : return rc4 inital box with key                                                                 
///****************************************************************************
rc4::rc4(const uint8_t *key, int key_length){
    for (int i = 0; i < 256; i++) {
        this->box[i] = (uint8_t)i;
        this->k[i] = key[i % key_length];
    }
    int j = 0;
    uint8_t temp = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + this->box[i] + this->k[i]) % 256;
        temp = this->box[i];
        this->box[i] = this->box[j];
        this->box[j] = temp;
    }
}


///****************************************************************************                 
/// @brief   :                                                                 
///****************************************************************************
void rc4::rc4keystream(uint8_t* stream, unsigned long long int length)
{
    uint8_t temp = 0;
    for (unsigned long long k = 0; k < length; k++) {
        this->box_i = (this->box_i + 1) % 256;
        this->box_j = (this->box_j + box[this->box_i]) % 256;
        temp = box[this->box_i];
        box[this->box_i] = box[this->box_j];
        box[this->box_j] = temp;
        *(stream + k) = box[(box[this->box_i] + box[this->box_j]) % 256];
    }
}

void rc4::rc4decrypt(uint8_t* plaintext, uint8_t* ciphertext, unsigned long long int length)
{

        try {
            uint8_t* stream = new uint8_t[length];
            rc4keystream(stream, length);
            for (unsigned long long  j = 0; j < length; j++) {
                *(ciphertext++) = stream[j] ^ *(plaintext++);
            }
            delete stream;
        }
        catch (std::exception& e) {
            std::cout << "Standard exception: " << e.what() << std::endl;
        }
}
