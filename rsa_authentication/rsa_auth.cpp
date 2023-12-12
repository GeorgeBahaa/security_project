#include "rsa_auth.h"
#include <openssl/err.h>
#include <iostream>

namespace project {

    namespace rsa_authentication{
        RSA_Authentication::RSA_Authentication() : rsaKeyPair(nullptr) {
            OpenSSL_add_all_algorithms();
            ERR_load_crypto_strings();
        }

        RSA_Authentication::~RSA_Authentication() {
            freeKeyPair();
            ERR_free_strings();
        }

        void RSA_Authentication::generateKeyPair() {
            freeKeyPair();
            rsaKeyPair = RSA_new();
            BIGNUM *bne = BN_new();
            BN_set_word(bne, RSA_F4); // Set the public exponent to 65537
            RSA_generate_key_ex(rsaKeyPair, 1024, bne, nullptr);
            BN_free(bne);
        }


        void RSA_Authentication::savePublicKey(const char *filename) {
            BIO *bio = BIO_new_file(filename, "w");
            PEM_write_bio_RSAPublicKey(bio, rsaKeyPair);
            BIO_free(bio);
        }

        void RSA_Authentication::savePrivateKey(const char *filename) {
            BIO *bio = BIO_new_file(filename, "w");
            PEM_write_bio_RSAPrivateKey(bio, rsaKeyPair, nullptr, nullptr, 0, nullptr, nullptr);
            BIO_free(bio);
        }

        bool RSA_Authentication::loadPublicKey(const char* filename) {
            freeKeyPair();

            BIO* bio = BIO_new_file(filename, "r");
            if (!bio) {
                std::cerr << "Error opening public key file." << std::endl;
                return false;
            }

            rsaKeyPair = PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);

            if (!rsaKeyPair) {
                std::cerr << "Error reading public key from file." << std::endl;
                ERR_print_errors_fp(stderr);
                return false;
            }

            return true;
        }

        bool RSA_Authentication::loadPrivateKey(const char* filename) {
            freeKeyPair();

            BIO* bio = BIO_new_file(filename, "r");
            if (!bio) {
                std::cerr << "Error opening private key file." << std::endl;
                return false;
            }

            rsaKeyPair = PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr);
            BIO_free(bio);

            if (!rsaKeyPair) {
                std::cerr << "Error reading private key from file." << std::endl;
                ERR_print_errors_fp(stderr);
                return false;
            }
            return true;
        }


        std::string RSA_Authentication::signMessage(const std::string &message) {
            if (!rsaKeyPair) {
                std::cerr << "Error: RSA key pair not initialized." << std::endl;
                return "";
            }

            unsigned char *signature = new unsigned char[RSA_size(rsaKeyPair)];
            unsigned int signatureLength;

            RSA_sign(NID_sha256, reinterpret_cast<const unsigned char *>(message.c_str()), message.length(), signature,
                     &signatureLength, rsaKeyPair);

            std::string signatureStr(reinterpret_cast<char *>(signature), signatureLength);
            delete[] signature;

            return signatureStr;
        }

        bool RSA_Authentication::verifySignature(const std::string &message, const std::string &signature) {
            // Check if the key pair is initialized
            if (!rsaKeyPair) {
                std::cerr << "Error: RSA key pair not initialized." << std::endl;
                return false;
            }

            // Perform signature verification using the public key
            int result = RSA_verify(NID_sha256,
                                    reinterpret_cast<const unsigned char *>(message.c_str()), message.length(),
                                    reinterpret_cast<const unsigned char *>(signature.c_str()), signature.length(),
                                    rsaKeyPair);

            // Check the verification result
            if (result == 1) {
                // Verification successful
                return true;
            } else if (result == 0) {
                // Verification failed
                std::cerr << "Signature verification failed." << std::endl;
            } else {
                // Error during verification
                std::cerr << "Error verifying signature." << std::endl;
                ERR_print_errors_fp(stderr);
            }

            return false;
        }

        void RSA_Authentication::freeKeyPair() {
            if (rsaKeyPair) {
                RSA_free(rsaKeyPair);
                rsaKeyPair = nullptr;
            }
        }

        void RSA_Authentication::autheticate(void) {
            // Generate RSA key pair
            this->generateKeyPair();

            // Save public key to file
            this->savePublicKey("public_key.pem");

            // Save private key to file
            this->savePrivateKey("private_key.pem");

            // Load public key from file
            if (this->loadPublicKey("public_key.pem")) {
                std::cout << "Public key loaded successfully." << std::endl;
            } else {
                std::cerr << "Error loading public key." << std::endl;
                ERR_print_errors_fp(stderr); // Print OpenSSL error stack
                return ; // Exit the program due to the error
            }

            // Load private key from file
            if (this->loadPrivateKey("private_key.pem")) {
                std::cout << "Private key loaded successfully." << std::endl;
            } else {
                std::cerr << "Error loading private key." << std::endl;
                ERR_print_errors_fp(stderr); // Print OpenSSL error stack
                return ; // Exit the program due to the error
            }


            // Sign a message using the private key
            std::string messageToSign = "Hello, RSA!";
            std::string signature = this->signMessage(messageToSign);

            if (this->loadPublicKey("public_key.pem")) {
                // Call verifySignature using loaded public key
                if (this->verifySignature(messageToSign, signature)) {
                    std::cout << "Authentication successful!" << std::endl;
                } else {
                    std::cerr << "Authentication failed: Signature verification failed." << std::endl;
                }
            } else {
                std::cerr << "Error loading public key." << std::endl;
            }


        }
    }
}
