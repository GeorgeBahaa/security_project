#ifndef RSA_AUTHENTICATION_H
#define RSA_AUTHENTICATION_H

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <string>

#define KEY_SIZE 2048
#define HASH_SIZE 256

namespace project
{
    namespace rsa_authentication
    {
        class RSA_Authentication
        {
        public:
            RSA_Authentication();

            ~RSA_Authentication();

            // Generate RSA key pair
            void generateKeyPair();

            // Save public key to file
            void savePublicKey(const char *filename);

            // Save private key to file
            void savePrivateKey(const char *filename);

            // Load public key from file
            bool loadPublicKey(const char *filename);

            // Load private key from file
            bool loadPrivateKey(const char *filename);

            // Sign a message using the private key
            std::string signMessage(const std::string &message);

            // Verify the signature of a message using the public key
            bool verifySignature(const std::string &message, const std::string &signature);

            void autheticate(void);

            void setMessageToSign(std::string message);

            std::string getMessageToSign();

            void rsa_conf_auth(void);
            void saveBinaryFile(const std::string &file_path, const std::string &data);
            std::string readBinaryFile(const std::string &path);
            void sign(void);
            void sign_enc(void);

        private:
            RSA *rsaKeyPair;

            std::string messageToSign;

            // Helper function to free RSA key pair
            void freeKeyPair();
        };
    }
}
#endif // RSA_AUTHENTICATION_H
