#include <iostream>
#include <cstring> // for strcpy
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "openssl_rsa.h"

using namespace std;

namespace project
{
    namespace rsa_enc_dec
    {
        // Setter
        void RSA_algorithm::setMessage(const std::string& newMessage)
        {
            
            // Make sure to copy the string into the array
            std::strncpy(message, newMessage.c_str(), sizeof(message) - 1);
            message[sizeof(message) - 1] = '\0'; // Null-terminate the string
        }

        // Getter
        const char* RSA_algorithm::getMessage()
        {
            return message;
        }

        RSA *RSA_algorithm::create_RSA_BIO(RSA *keypair, int pem_type, const char *bio_name)
        {
            RSA *rsa = nullptr;
            BIO *bio = BIO_new_file(bio_name, "w+");

            if (pem_type == PUBLIC_KEY_PEM)
            {
                PEM_write_bio_RSAPublicKey(bio, keypair);
                BIO_reset(bio);
                PEM_read_bio_RSAPublicKey(bio, &rsa, nullptr, nullptr);
            }
            else if (pem_type == PRIVATE_KEY_PEM)
            {
                PEM_write_bio_RSAPrivateKey(bio, keypair, nullptr, nullptr, 0, nullptr, nullptr);
                BIO_reset(bio);
                PEM_read_bio_RSAPrivateKey(bio, &rsa, nullptr, nullptr);
            }

            BIO_free(bio);
            return rsa;
        }

        int RSA_algorithm::public_encrypt(int flen, unsigned char *from, unsigned char *to, RSA *key, int padding)
        {

            int result = RSA_public_encrypt(flen, from, to, key, padding);
            return result;
        }

        int RSA_algorithm::private_decrypt(int flen, unsigned char *from, unsigned char *to, RSA *key, int padding)
        {
            int result = RSA_private_decrypt(flen, from, to, key, padding);
            if (result == -1)
            {
                // An error occurred during encryption
                ERR_print_errors_fp(stderr);
            }
            return result;
        }

        void RSA_algorithm::create_encrypted_file_BIO(char *encrypted, RSA *key_pair)
        {
            BIO *bio = BIO_new_file("encrypted_file.bin", "w");
            BIO_write(bio, encrypted, RSA_size(key_pair));
            BIO_free(bio);
        }

        void RSA_algorithm::create_decrypted_file_BIO(char *decrypted, int decrypt_length)
        {
            BIO *bio = BIO_new_file("decrypted_file.txt", "w");

            if (bio)
            {
                BIO_write(bio, decrypted, decrypt_length);
                BIO_free(bio);
                cout << "Decrypted file has been created." << endl;
            }
            else
            {
                // Handle error if BIO creation fails
                cout << "Error creating BIO for writing decrypted file." << endl;
            }
        }

        void RSA_algorithm::run_algorithm(void)
        {
            cout << "starting RSA algorithm ... " << endl;

            /* for storing key pairs*/
            RSA *private_key;
            RSA *public_key;

            /* pointers to ciphertext and decrypted text */
            char *encrypt = nullptr;
            char *decrypt = nullptr;

            RSA *keypair = nullptr;
            BIGNUM *bigNum = nullptr;
            int status = 0;

            char private_key_pem[12] = "private_key";
            char public_key_pem[11] = "public_key";

            RSA_algorithm *rsaAlgorithm;

            cout << KEY_SIZE << endl;
            cout << PUBLIC_EXPONENT << endl;

            bigNum = BN_new();
            status = BN_set_word(bigNum, PUBLIC_EXPONENT);
            if (status != 1)
            {
                cout << "An error occurred in BN_set_word() method" << endl;
            }

            keypair = RSA_new();
            status = RSA_generate_key_ex(keypair, KEY_SIZE, bigNum, nullptr);
            if (status != 1)
            {
                cout << ("An error occurred in RSA_generate_key_ex() method");
            }
            cout << "key is generated" << endl;

            private_key = rsaAlgorithm->create_RSA_BIO(keypair, PRIVATE_KEY_PEM, private_key_pem);
            cout << "private_key.txt file is created." << endl;

            public_key = rsaAlgorithm->create_RSA_BIO(keypair, PUBLIC_KEY_PEM, public_key_pem);
            cout << "Public key pem file has been created." << endl;

            encrypt = (char *)malloc(RSA_size(public_key));
            int encrypt_length = rsaAlgorithm->public_encrypt(strlen(message) + 1, (unsigned char *)message,
                                                              (unsigned char *)encrypt,
                                                              public_key, RSA_PKCS1_OAEP_PADDING);
            if (encrypt_length == -1)
            {
                cout << "An error occurred in public_encrypt() method" << endl;
            }
            cout << "Data is encrypted successfully!" << endl;

            rsaAlgorithm->create_encrypted_file_BIO(encrypt, public_key);
            cout << "encrypted_file.bin is created " << endl;

            decrypt = (char *)malloc(encrypt_length);
            int decrypt_length = rsaAlgorithm->private_decrypt(encrypt_length, (unsigned char *)encrypt,
                                                               (unsigned char *)decrypt,
                                                               private_key, RSA_PKCS1_OAEP_PADDING);
            if (decrypt_length == -1)
            {
                cout << "An error occurred in private_decrypt() method" << endl;
            }
            cout << "Data is decrypted successfully!" << endl;

            rsaAlgorithm->create_decrypted_file_BIO(decrypt, decrypt_length);
            cout << "decrypted_file.txt is created" << endl;

            RSA_free(keypair);
            free(private_key);
            free(public_key);
            free(encrypt);
            free(decrypt);
            BN_free(bigNum);
        }
    }
}