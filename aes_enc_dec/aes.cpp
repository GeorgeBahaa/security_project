#include "aes.h"
#include <fstream>
#include <sstream>

namespace project
{
    namespace aes
    {
        void handleErrors()
        {
            std::cerr << "Error occurred." << std::endl;
            exit(EXIT_FAILURE);
        }

        void saveBinaryFile(const std::string &file_path, const std::string &data)
        {
            std::ofstream file(file_path, std::ios::binary);

            if (file)
            {
                file.write(data.c_str(), data.size());
                file.close();
            }
            else
            {
                std::cerr << "Error opening the file for writing: " << file_path << std::endl;
            }
        }

        std::string readBinaryFile(const std::string &path)
        {

            // Open the file
            std::ifstream inputFile(path, std::ios::binary);

            if (inputFile)
            {
                // Read the entire file into a string
                std::ostringstream content;
                content << inputFile.rdbuf();
                inputFile.close();

                return content.str();
            }
            else
            {
                std::cerr << "Error opening the file: " << path << std::endl;
                return ""; // Return an empty string if there's an error
            }
        }

        // Padding function
        void addPadding(std::string &data)
        {
            char padding = AES_BLOCK_SIZE - data.size() % AES_BLOCK_SIZE;
            data.append(padding, padding);
        }

        void encrypt(const std::string &plaintext, const std::string &key, std::vector<unsigned char> &ciphertext)
        {
            AES_KEY encryptKey;
            if (AES_set_encrypt_key(reinterpret_cast<const unsigned char *>(key.c_str()), 128, &encryptKey) < 0)
            {
                handleErrors();
            }

            std::string paddedPlaintext = plaintext;
            addPadding(paddedPlaintext);

            // Determine the size of the ciphertext and resize the vector
            size_t ciphertextSize = paddedPlaintext.size();
            ciphertext.resize(ciphertextSize);

            // Encrypt block by block
            for (size_t i = 0; i < paddedPlaintext.size(); i += AES_BLOCK_SIZE)
            {
                AES_encrypt(reinterpret_cast<const unsigned char *>(&paddedPlaintext[i]), &ciphertext[i], &encryptKey);
            }
        }

        void decrypt(const std::vector<unsigned char> &ciphertext, const std::string &key, std::vector<char> &decryptedtext)
        {
            AES_KEY decryptKey;
            if (AES_set_decrypt_key(reinterpret_cast<const unsigned char *>(key.c_str()), 128, &decryptKey) < 0)
            {
                handleErrors();
            }

            // Resize the decryptedtext vector to hold the decrypted text
            decryptedtext.resize(ciphertext.size());

            // Decrypt block by block
            for (size_t i = 0; i < ciphertext.size(); i += AES_BLOCK_SIZE)
            {
                AES_decrypt(&ciphertext[i], reinterpret_cast<unsigned char *>(&decryptedtext[i]), &decryptKey);
            }

            // Remove padding
            size_t paddingSize = decryptedtext.back();
            decryptedtext.resize(decryptedtext.size() - paddingSize);
        }

        std::string generateKey()
        {
            const size_t keySize = 16; // 128 bits key size
            std::string key;

            srand(static_cast<unsigned int>(time(nullptr)));

           const std::string allowedChars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

            for (size_t i = 0; i < keySize; ++i)
            {
                char randomChar = allowedChars[rand() % allowedChars.size()];
                key.push_back(randomChar);
            }

            return key;
        }

        bool isValidKey(const std::string &key)
        {
            // AES-128 requires a 16-byte key
            return (key.size() == 16);
        }

        void aes_enc(std::string &plaintext, std::string &key)
        {
            //std::string key = "0123456789abcdef"; // 128-bit key

            // Encryption
            std::vector<unsigned char> ciphertext;
            project::aes::encrypt(plaintext, key, ciphertext);

            std::string encrypted_path = "aes_encrypted.bin";
            std::string cipherString(ciphertext.begin(), ciphertext.end());

            saveBinaryFile(encrypted_path, cipherString);

            cout << "Data is encrypted successfully!" << endl;
            cout << "aes_encrypted.bin is saved in build directory! \n"
                 << endl;

            cout << "AES Encryption done successfully.\n"
                 << endl;
        }

        void aes_go(std::string &plaintext, std::string &key)
        {

            //std::string key = "0123456789abcdef"; // 128-bit key
            // Encryption
            std::vector<unsigned char> ciphertext;
            project::aes::encrypt(plaintext, key, ciphertext);

            cout << "Data is encrypted successfully!" << endl;
            std::string encrypted_path = "aes_encrypted.bin";
            std::string cipherString(ciphertext.begin(), ciphertext.end());

            saveBinaryFile(encrypted_path, cipherString);
            cout << "aes_encrypted.bin is saved in build directory! \n"
                 << endl;

            std::string encString = readBinaryFile(encrypted_path);
            std::vector<unsigned char> readciphertext(encString.begin(), encString.end());

            std::vector<char> decryptedtext;
            // Decryption
            project::aes::decrypt(readciphertext, key, decryptedtext);
            cout << "Data is decrypted successfully!" << endl;
            std::string afterdec(decryptedtext.begin(), decryptedtext.end());

            std::string decrypted_path = "aes_decrypted.txt";
            saveBinaryFile(decrypted_path, afterdec);
            cout << "aes_decrypted.txt is saved in build directory! \n"
                 << endl;

            std::cout << "Encrypted Text: " << plaintext << std::endl;
            std::cout << "Decrypted Text: " << afterdec << std::endl;

            if (plaintext == afterdec)
            {

                cout << "\nAES Encryption/Decryption done successfully.\n"
                     << endl;
            }
        }
    }
}
