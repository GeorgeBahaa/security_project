#ifndef AES_H
#define AES_H

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <iostream>
#include <iomanip>

namespace project {
    namespace aes {

        void handleErrors();

        void encrypt(const char *plaintext, const char *key, unsigned char *ciphertext);

        void decrypt(const unsigned char *ciphertext, const char *key, char *decryptedtext);

    } // namespace aes
} // namespace project

#endif // AES_H
