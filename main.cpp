#include "rsa_encryption_decryption/openssl_rsa.h"
#include "rsa_authentication/rsa_auth.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <openssl/err.h>
#include "aes_enc_dec/aes.h"

using namespace std;
using namespace project::rsa_enc_dec;
using namespace project::rsa_authentication;
using namespace project::aes;

typedef enum
{
    AES = 1,
    RSA_ENC,
    RSA_SIGN,
    RSA_ENC_SIGN
} operation;

std::string read_message(const std::string &path)
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

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        std::cerr << "Please enter the path as first argument\n"
                  << "In format of: .\\project.exe \"path\""
                  << std::endl;

        return 1; // Exit with an error code
    }
    int x;
    int y;
    bool isvalid=true;
    std::string key;
    std::string file_path = argv[1];
    std::string message = read_message(file_path);
    std::cout << message << std::endl;

    while (1)
    {
        std::cout << "\n[1] AES Encryption/Decryption\n"
                  << "[2] RSA Encryption/Decryption\n"
                  << "[3] RSA sign/verify\n"
                  << "[4] Confidentiality and Authentication\n\n"
                  << std::endl;
        do
        {
            std::cout << "Please choose operation \n";
            std::cin >> x;
            std::cout << std::endl;
        } while (x > 4 || x < 1);

        switch (x)
        {
        case AES:
        {
            /************** AES enc/dec **************/
            std::cout << "\n[1] Encrypt\n"
                      << "[2] Encrypt/Decrypt\n\n"
                      << std::endl;
            do
            {
                std::cout << "Please choose operation \n";
                std::cin >> x;
                std::cout << std::endl;
            } while (x > 2 || x < 1);

            std::cout << "\n[1] Generate key automatically\n"
                      << "[2] Enter key manually\n\n"
                      << std::endl;
            do
            {
                std::cout << "Please choose operation \n";
                std::cin >> y;
                std::cout << std::endl;
            } while (y > 2 || y < 1);

             switch (x)
            {
            case 1:
            {
                if (y == 1)
                {
                    key = generateKey();
                    aes_enc(message,key);
                }
                else if(y==2)
                {
                    while(isvalid)
                    {
                    std::cout << "Please Enter valid key (128-bit key) \n";
                    std::cin >> key;
                    std::cout << std::endl;
                    if(!isValidKey(key))
                    {
                        std::cout << "not valid key \n" << std::endl;
                    }
                    else{
                        isvalid=false;
                    }
                    }

                    aes_enc(message,key);
                }
                break;
            }
            case 2:
            {
                if (y == 1)
                {
                    key = generateKey();
                    aes_go(message,key);
                }
                else if(y==2)
                {
                    while(isvalid)
                    {
                    std::cout << "Please Enter valid key (128-bit key) \n";
                    std::cin >> key;
                    std::cout << std::endl;
                    if(!isValidKey(key))
                    {
                        std::cout << "not valid key \n" << std::endl;
                    }
                    else{
                        isvalid=false;
                    }
                    }
                    aes_go(message,key);
                }
                    break;
            }
            default:
                break;
            }
            break;
        }
        case RSA_ENC:
        {
            /************** RSA enc/dec **************/
            std::cout << "\n[1] Encrypt\n"
                      << "[2] Encrypt/Decrypt\n\n"
                      << std::endl;
            do
            {
                std::cout << "Please choose operation \n";
                std::cin >> x;
                std::cout << std::endl;
            } while (x > 2 || x < 1);

            RSA_algorithm rsa_algorithm;
            rsa_algorithm.setMessage(message);
            switch (x)
            {
            case 1:
            {
                rsa_algorithm.encrypt();
                break;
            }
            case 2:
            {
                rsa_algorithm.run_algorithm();
                break;
            }
            default:
                break;
            }

            break;
        }
        case RSA_SIGN:
        {
            /************* RSA sign/verify ******************/
            std::cout << "\n[1] Sign\n"
                      << "[2] Sign/Verify\n\n"
                      << std::endl;
            do
            {
                std::cout << "Please choose operation \n";
                std::cin >> x;
                std::cout << std::endl;
            } while (x > 2 || x < 1);

            RSA_Authentication *rsaAuthentication = new RSA_Authentication();
            rsaAuthentication->setMessageToSign(message);

            switch (x)
            {
            case 1:
            {
                rsaAuthentication->sign();
                break;
            }

            case 2:
            {
                rsaAuthentication->autheticate();
                break;
            }

            default:
                break;
            }

            break;
        }
        case RSA_ENC_SIGN:
        {
            /************* RSA sign/verify ******************/
            std::cout << "\n[1] Sign\n"
                      << "[2] Sign + Encrypt\n"
                      << "[3] Sign + Encrypt/Decrypt + Verify\n\n"
                      << std::endl;
            do
            {
                std::cout << "Please choose operation \n";
                std::cin >> x;
                std::cout << std::endl;
            } while (x > 3 || x < 1);

            RSA_Authentication *rsaAuthentication = new RSA_Authentication();
            rsaAuthentication->setMessageToSign(message);

            switch (x)
            {
            case 1:
            {
                rsaAuthentication->sign();
                break;
            }

            case 2:
            {
                rsaAuthentication->sign_enc();
                break;
            }

            case 3:
            {
                rsaAuthentication->rsa_conf_auth();
                break;
            }

            default:
                break;
            }

            break;
        }
        default:
            break;
        }
    }

}
