#ifndef RSA_H
#define RSA_H

#include <openssl/types.h>
#include <string>

#define KEY_SIZE 2048
#define PUBLIC_EXPONENT 65537
#define PUBLIC_KEY_PEM 1
#define PRIVATE_KEY_PEM 0

namespace project
{
    namespace rsa_enc_dec
    {

        class RSA_algorithm
        {
        private:
            char message[KEY_SIZE / 8];

        public:
            void setMessage(const std::string& newMessage);

            const char* getMessage();
            /**
             *This function essentially provides a way to write an RSA key to a BIO file and then read it back.
             * @param keypair  The input RSA keypair that you want to read or write.
             * @param pem_type Specifies whether it's a public key or private key operation (PUBLIC_KEY_PEM or PRIVATE_KEY_PEM).
             * @param bio_name The name of the BIO (Basic I/O) file.
             * @return  The function returns a pointer to an RSA structure, representing the RSA key.
             */
            RSA *create_RSA_BIO(RSA *keypair, int pem_type, const char *bio_name);

            /**
             * function performs RSA public key encryption on the input data (from) using the specified RSA public key (key). The result is stored in the to buffer.
             * @param flen the length of the input data in bytes (from buffer).
             * @param from: A pointer to the input data (plaintext) that you want to encrypt.
             * @param to   A pointer to the buffer where the encrypted data (ciphertext) will be stored. The size of this buffer should be at least the size of the RSA modulus
             * @param key  A pointer to the RSA public key used for encryption. This key should typically be the public key of the recipient.
             * @param padding The padding scheme to be used during encryption. Common padding options include RSA_PKCS1_PADDING and RSA_NO_PADDING.
             * @return The return value of RSA_public_encrypt is the size of the encrypted data in bytes, or -1 if an error occurs
             */
            int public_encrypt(int flen, unsigned char *from, unsigned char *to, RSA *key, int padding);

            /**
             * Performs RSA private key decryption on the input data (from) using the specified RSA private key (key).
             * The decrypted data is stored in the to buffer.
             *
             * @param flen The length of the input data in bytes (from buffer).
             * @param from A pointer to the input data (ciphertext) that you want to decrypt.
             * @param to A pointer to the buffer where the decrypted data (plaintext) will be stored.
             * @param key A pointer to the RSA private key used for decryption.
             *            This key should be the private key corresponding to the public key used for encryption.
             * @param padding The padding scheme used during encryption.
             *                It should match the padding scheme used during encryption.
             *
             * @return The size of the decrypted data in bytes, or -1 if an error occurs.
             */
            int private_decrypt(int flen, unsigned char *from, unsigned char *to, RSA *key, int padding);

            /**
             * Creates a binary file and writes the encrypted data from the provided buffer to that file.
             *
             * @param encrypted A pointer to the buffer containing the encrypted data (ciphertext).
             * @param key_pair A pointer to the RSA key pair used for encryption.
             *
             * @return None.
             */
            void create_encrypted_file_BIO(char *encrypted, RSA *key_pair);

            /**
             * Creates a binary file named "decrypted_file.txt" and writes the decrypted data to that file using BIO.
             *
             * @param decrypted A pointer to the buffer containing the decrypted data.
             * @param decrypt_length The length of the decrypted data in bytes.
             *
             * @return None.
             */

            void create_decrypted_file_BIO(char *decrypted, int decrypt_length);

            /**
             * run the overall algorithm and call above functions in right sequence
             */

            void run_algorithm(void);
        };
    }
}

#endif // RSA_H