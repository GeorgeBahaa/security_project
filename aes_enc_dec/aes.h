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

        void aes_go(std::string &plaintext);
        void saveBinaryFile(const std::string &file_path, const std::string &data);
        std::string readBinaryFile(const std::string &path);
        void aes_enc(std::string &plaintext);

    } // namespace aes
} // namespace project

#endif // AES_H
