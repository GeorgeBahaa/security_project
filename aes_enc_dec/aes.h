#ifndef AES_H
#define AES_H

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <cstring>
#include <vector>

using namespace std;
namespace project
{
    namespace aes
    {

        void handleErrors();

        void encrypt(const std::string &plaintext, const std::string &key, std::vector<unsigned char> &ciphertext);

        void decrypt(const std::vector<unsigned char> &ciphertext, const std::string &key, std::vector<char> &decryptedtext);

       
        void saveBinaryFile(const std::string &file_path, const std::string &data);
        std::string readBinaryFile(const std::string &path);
      
        void addPadding(std::string &data);

        std::string generateKey();
        bool isValidKey(const std::string &key);
        void aes_enc(std::string &plaintext, std::string &key);
        void aes_go(std::string &plaintext, std::string &key);

    } // namespace aes
} // namespace project

#endif // AES_H
