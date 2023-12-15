#include "aes.h"

using namespace std;

namespace project {
    namespace aes {
void handleErrors() {
    std::cerr << "Error occurred." << std::endl;
    exit(EXIT_FAILURE);
}

void encrypt(const char *plaintext, const char *key, unsigned char *ciphertext) {
    AES_KEY encryptKey;
    if (AES_set_encrypt_key(reinterpret_cast<const unsigned char *>(key), 128, &encryptKey) < 0) {
        handleErrors();
    }

    AES_encrypt(reinterpret_cast<const unsigned char *>(plaintext), ciphertext, &encryptKey);
}

void decrypt(const unsigned char *ciphertext, const char *key, char *decryptedtext) {
    AES_KEY decryptKey;
    if (AES_set_decrypt_key(reinterpret_cast<const unsigned char *>(key), 128, &decryptKey) < 0) {
        handleErrors();
    }

    AES_decrypt(ciphertext, reinterpret_cast<unsigned char *>(decryptedtext), &decryptKey);
}

}
}