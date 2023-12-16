#ifndef AES_H
#define AES_H

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <vector>

namespace project {
    namespace aes {

        void handleErrors();
        
        void encrypt(const std::string& plaintext, const std::string& key, std::vector<unsigned char>& ciphertext);
        
        void decrypt(const std::vector<unsigned char>& ciphertext, const std::string& key, std::vector<char>& decryptedtext);

        void aes_go(std::string &plaintext);

    } // namespace aes
} // namespace project

#endif // AES_H
