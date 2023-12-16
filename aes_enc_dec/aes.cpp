#include "aes.h"

namespace project {
    namespace aes {
        void handleErrors() {
            std::cerr << "Error occurred." << std::endl;
            exit(EXIT_FAILURE);
        }

        // Padding function
        void addPadding(std::string& data) {
            char padding = AES_BLOCK_SIZE - data.size() % AES_BLOCK_SIZE;
            data.append(padding, padding);
        }

        void encrypt(const std::string& plaintext, const std::string& key, std::vector<unsigned char>& ciphertext) {
            AES_KEY encryptKey;
            if (AES_set_encrypt_key(reinterpret_cast<const unsigned char*>(key.c_str()), 128, &encryptKey) < 0) {
                handleErrors();
            }

            std::string paddedPlaintext = plaintext;
            addPadding(paddedPlaintext);

            // Determine the size of the ciphertext and resize the vector
            size_t ciphertextSize = paddedPlaintext.size();
            ciphertext.resize(ciphertextSize);

            // Encrypt block by block
            for (size_t i = 0; i < paddedPlaintext.size(); i += AES_BLOCK_SIZE) {
                AES_encrypt(reinterpret_cast<const unsigned char*>(&paddedPlaintext[i]), &ciphertext[i], &encryptKey);
            }
        }

        void decrypt(const std::vector<unsigned char>& ciphertext, const std::string& key, std::vector<char>& decryptedtext) {
            AES_KEY decryptKey;
            if (AES_set_decrypt_key(reinterpret_cast<const unsigned char*>(key.c_str()), 128, &decryptKey) < 0) {
                handleErrors();
            }

            // Resize the decryptedtext vector to hold the decrypted text
            decryptedtext.resize(ciphertext.size());

            // Decrypt block by block
            for (size_t i = 0; i < ciphertext.size(); i += AES_BLOCK_SIZE) {
                AES_decrypt(&ciphertext[i], reinterpret_cast<unsigned char*>(&decryptedtext[i]), &decryptKey);
            }

            // Remove padding
            size_t paddingSize = decryptedtext.back();
            decryptedtext.resize(decryptedtext.size() - paddingSize);
        }
    }
}
