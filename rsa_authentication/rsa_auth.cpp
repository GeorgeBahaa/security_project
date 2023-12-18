#include "rsa_auth.h"
#include <openssl/err.h>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <tuple>
#include "../aes_enc_dec/aes.h"

namespace project
{
    namespace rsa_authentication
    {
        void RSA_Authentication::setMessageToSign(const std::string message)
        {
            this->messageToSign = message;
        }

        std::string RSA_Authentication::getMessageToSign()
        {
            return this->messageToSign;
        }

        RSA_Authentication::RSA_Authentication() : rsaKeyPair(nullptr)
        {
            OpenSSL_add_all_algorithms();
            ERR_load_crypto_strings();
        }

        RSA_Authentication::~RSA_Authentication()
        {
            freeKeyPair();
            ERR_free_strings();
        }
        void RSA_Authentication::saveBinaryFile(const std::string &file_path, const std::string &data)
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

        std::string RSA_Authentication::readBinaryFile(const std::string &path)
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

        void RSA_Authentication::generateKeyPair()
        {
            freeKeyPair();
            rsaKeyPair = RSA_new();
            BIGNUM *bne = BN_new();
            BN_set_word(bne, RSA_F4); // Set the public exponent to 65537
            RSA_generate_key_ex(rsaKeyPair, KEY_SIZE, bne, nullptr);
            BN_free(bne);
        }

        void RSA_Authentication::savePublicKey(const char *filename)
        {
            BIO *bio = BIO_new_file(filename, "w");
            PEM_write_bio_RSAPublicKey(bio, rsaKeyPair);
            BIO_free(bio);
        }

        void RSA_Authentication::savePrivateKey(const char *filename)
        {
            BIO *bio = BIO_new_file(filename, "w");
            PEM_write_bio_RSAPrivateKey(bio, rsaKeyPair, nullptr, nullptr, 0, nullptr, nullptr);
            BIO_free(bio);
        }

        bool RSA_Authentication::loadPublicKey(const char *filename)
        {
            freeKeyPair();

            BIO *bio = BIO_new_file(filename, "r");
            if (!bio)
            {
                std::cerr << "Error opening public key file." << std::endl;
                return false;
            }

            rsaKeyPair = PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);

            if (!rsaKeyPair)
            {
                std::cerr << "Error reading public key from file." << std::endl;
                ERR_print_errors_fp(stderr);
                return false;
            }

            return true;
        }

        bool RSA_Authentication::loadPrivateKey(const char *filename)
        {
            freeKeyPair();

            BIO *bio = BIO_new_file(filename, "r");
            if (!bio)
            {
                std::cerr << "Error opening private key file." << std::endl;
                return false;
            }

            rsaKeyPair = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);

            if (!rsaKeyPair)
            {
                std::cerr << "Error reading private key from file." << std::endl;
                ERR_print_errors_fp(stderr);
                return false;
            }
            return true;
        }

        std::string RSA_Authentication::signMessage(const std::string &message)
        {
            if (!rsaKeyPair)
            {
                std::cerr << "Error: RSA key pair not initialized." << std::endl;
                return "";
            }

            unsigned char *signature = new unsigned char[RSA_size(rsaKeyPair)];
            unsigned int signatureLength;

            RSA_sign(NID_sha512, reinterpret_cast<const unsigned char *>(message.c_str()), message.length(), signature,
                     &signatureLength, rsaKeyPair);

            std::string signatureStr(reinterpret_cast<char *>(signature), signatureLength);
            delete[] signature;

            return signatureStr;
        }

        bool RSA_Authentication::verifySignature(const std::string &message, const std::string &signature)
        {
            // Check if the key pair is initialized
            if (!rsaKeyPair)
            {
                std::cerr << "Error: RSA key pair not initialized." << std::endl;
                return false;
            }

            // Perform signature verification using the public key
            int result = RSA_verify(NID_sha512,
                                    reinterpret_cast<const unsigned char *>(message.c_str()), message.length(),
                                    reinterpret_cast<const unsigned char *>(signature.c_str()), signature.length(),
                                    rsaKeyPair);

            // Check the verification result
            if (result == 1)
            {
                // Verification successful
                return true;
            }
            else if (result == 0)
            {
                // Verification failed
                std::cerr << "Signature verification failed." << std::endl;
            }
            else
            {
                // Error during verification
                std::cerr << "Error verifying signature." << std::endl;
                ERR_print_errors_fp(stderr);
            }

            return false;
        }

        void RSA_Authentication::freeKeyPair()
        {
            if (rsaKeyPair)
            {
                RSA_free(rsaKeyPair);
                rsaKeyPair = nullptr;
            }
        }

        void RSA_Authentication::sign(void)
        {
            // Generate RSA key pair
            this->generateKeyPair();

            // Save public key to file
            this->savePublicKey("public_key.pem");

            // Save private key to file
            this->savePrivateKey("private_key.pem");

            std::string signature = "";
            // Load private key from file
            if (this->loadPrivateKey("private_key.pem"))
            {
                // std::cout << "Private key loaded successfully." << std::endl;
                //  Sign a message using the private key
                signature = this->signMessage(messageToSign);
            }
            else
            {
                std::cerr << "Error loading private key." << std::endl;
                ERR_print_errors_fp(stderr); // Print OpenSSL error stack
                return;                      // Exit the program due to the error
            }

            std::string signature_path = "auth_signature.bin";

            saveBinaryFile(signature_path, signature);

            std::cout << "auth_signature.bin is saved in build directory!\n"
                      << std::endl;

            std::cout << "Public and Private keys(.pem) files are saved in build directory!"
                      << std::endl;

            std::cout << "\nRSA Sign done successfully." << std::endl;
        }

        void RSA_Authentication::sign_enc(void)
        {
            // Generate RSA key pair
            this->generateKeyPair();

            // Save public key to file
            this->savePublicKey("public_key.pem");

            // Save private key to file
            this->savePrivateKey("private_key.pem");

            std::string signature = "";
            // Load private key from file
            if (this->loadPrivateKey("private_key.pem"))
            {
                // std::cout << "Private key loaded successfully." << std::endl;
                //  Sign a message using the private key
                signature = this->signMessage(messageToSign);
            }
            else
            {
                std::cerr << "Error loading private key." << std::endl;
                ERR_print_errors_fp(stderr); // Print OpenSSL error stack
                return;                      // Exit the program due to the error
            }

            std::string appendedString = signature + messageToSign;

            std::string appendedString_path = "appendedString.bin";
            std::string signature_path = "signature.bin";

            saveBinaryFile(appendedString_path, appendedString);
            saveBinaryFile(signature_path, signature);

            // Encrypt and decrypt using AES
            std::string key = project::aes::generateKey();
            std::vector<unsigned char> ciphertext;
            project::aes::encrypt(appendedString, key, ciphertext);

            std::string encCipherText(ciphertext.begin(), ciphertext.end());
            std::string ciphertext_path = "ciphertext.bin";
            saveBinaryFile(ciphertext_path, encCipherText);

            std::cout << "appendedString.bin is saved in build directory!\n"
                      << "signature.bin is saved in build directory!\n"
                      << "ciphertext.bin is saved in build directory!\n"
                      << std::endl;

            std::cout << "Public and Private keys(.pem) files are saved in build directory!"
                      << std::endl;

            std::cout << "\nRSA Sign+Encryption done successfully." << std::endl;
        }

        void RSA_Authentication::autheticate(void)
        {
            // Generate RSA key pair
            this->generateKeyPair();

            // Save public key to file
            this->savePublicKey("public_key.pem");

            // Save private key to file
            this->savePrivateKey("private_key.pem");

            std::string signature = "";
            // Load private key from file
            if (this->loadPrivateKey("private_key.pem"))
            {
                // std::cout << "Private key loaded successfully." << std::endl;
                //  Sign a message using the private key
                signature = this->signMessage(messageToSign);
            }
            else
            {
                std::cerr << "Error loading private key." << std::endl;
                ERR_print_errors_fp(stderr); // Print OpenSSL error stack
                return;                      // Exit the program due to the error
            }

            std::string signature_path = "auth_signature.bin";

            saveBinaryFile(signature_path, signature);
            std::string readsignature = readBinaryFile(signature_path);

            std::cout << "auth_signature.bin is saved in build directory!\n"
                      << std::endl;

            std::cout << "Public and Private keys(.pem) files are saved in build directory!"
                      << std::endl;

            if (this->loadPublicKey("public_key.pem"))
            {
                // Call verifySignature using loaded public key
                if (this->verifySignature(messageToSign, readsignature))
                {
                    std::cout << "\nRSA Sign/Verify done successfully." << std::endl;
                }
                else
                {
                    std::cerr << "Authentication failed: Signature verification failed." << std::endl;
                }
            }
            else
            {
                std::cerr << "Error loading public key." << std::endl;
            }
        }

        void RSA_Authentication::rsa_conf_auth(void)
        {

            // Generate RSA key pair
            this->generateKeyPair();

            // Save public key to file
            this->savePublicKey("public_key.pem");

            // Save private key to file
            this->savePrivateKey("private_key.pem");

            std::string signature = "";
            // Load private key from file
            if (this->loadPrivateKey("private_key.pem"))
            {
                // std::cout << "Private key loaded successfully." << std::endl;
                //  Sign a message using the private key
                signature = this->signMessage(messageToSign);
            }
            else
            {
                std::cerr << "Error loading private key." << std::endl;
                ERR_print_errors_fp(stderr); // Print OpenSSL error stack
                return;                      // Exit the program due to the error
            }

            std::string appendedString = signature + messageToSign;

            std::string appendedString_path = "appendedString.bin";
            std::string signature_path = "signature.bin";

            saveBinaryFile(appendedString_path, appendedString);
            saveBinaryFile(signature_path, signature);

            // Encrypt and decrypt using AES
            std::string key = "0123456789abcdef"; // 128-bit key
            std::vector<unsigned char> ciphertext;
            project::aes::encrypt(appendedString, key, ciphertext);

            std::string encCipherText(ciphertext.begin(), ciphertext.end());
            std::string ciphertext_path = "ciphertext.bin";
            saveBinaryFile(ciphertext_path, encCipherText);

            std::string encString = readBinaryFile(ciphertext_path);
            std::vector<unsigned char> readciphertext(encString.begin(), encString.end());

            std::vector<char> decryptedtext;
            project::aes::decrypt(readciphertext, key, decryptedtext);
            std::string afterdec(decryptedtext.begin(), decryptedtext.end());

            std::string newHash = afterdec.substr(0, HASH_SIZE);
            std::string newMessage = afterdec.substr(HASH_SIZE);

            std::cout << "appendedString.bin is saved in build directory!\n"
                      << "signature.bin is saved in build directory!\n"
                      << "ciphertext.bin is saved in build directory!\n"
                      << std::endl;

            std::cout << "Public and Private keys(.pem) files are saved in build directory!"
                      << std::endl;

            if (this->loadPublicKey("public_key.pem"))
            {
                // std::cout << "Public key loaded successfully." << std::endl;
                //  Call verifySignature using loaded public key
                if (this->verifySignature(newMessage, newHash))
                {
                    std::cout << "\nConfidentiality and Authentication done successfully." << std::endl;
                }
                else
                {
                    std::cerr << "Authentication failed: Signature verification failed." << std::endl;
                }
            }
            else
            {
                std::cerr << "Error loading public key." << std::endl;
            }
        }
    }
}