#include "rsa_encryption_decryption/openssl_rsa.h"
#include "rsa_authentication/rsa_auth.h"
#include <iostream>
#include <fstream>
#include <string>
#include <openssl/err.h>
#include "aes_enc_dec/aes.h"


using namespace std;
using namespace project::rsa_enc_dec;
using namespace project::rsa_authentication;
using namespace project::aes;


std::string read_message(std::string path){
    
    // Open the file
    std::ifstream inputFile(path);

    // Check if the file is open
    if (!inputFile.is_open()) {
        std::cerr << "Error opening file: " << path << std::endl;
        return "ERROR";
    }

    // Read the string from the file
    std::string message;
    std::getline(inputFile, message);

    // Close the file
    inputFile.close();

    return message;
}

int main()
{   
    //std::string message = read_message("E:/University/Semester 9/Computer and Network Security/Project/input.txt"); 

    /************** RSA enc/dec **************/
    // RSA_algorithm rsa_algorithm;
    // rsa_algorithm.setMessage(message);
    // rsa_algorithm.run_algorithm();

    /************* RSA sign/verify ******************/
    //RSA_Authentication *rsaAuthentication = new RSA_Authentication();
    //rsaAuthentication->setMessageToSign(message);
    // rsaAuthentication->autheticate();
    //rsaAuthentication->rsa_conf_auth();

    /////////////////////////////////////////////////////

    const char *key = "0123456789abcdef"; // 128-bit key
    const char *plaintext = "Hello, OpenSSL!";

    // AES operates on blocks of data, so we need to allocate space for the ciphertext
    unsigned char ciphertext[AES_BLOCK_SIZE];
    char decryptedtext[AES_BLOCK_SIZE];

    // Encrypt
    encrypt(plaintext, key, ciphertext);

    // Decrypt
    decrypt(ciphertext, key, decryptedtext);

    cout << "Original text: " << plaintext << endl;
    cout << "Encrypted text: ";
    for (int i = 0; i < AES_BLOCK_SIZE; ++i) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(ciphertext[i]);
    }
    cout << endl;
    cout << "Decrypted text: " << decryptedtext << endl;

    return 0;

   return 0;
}
