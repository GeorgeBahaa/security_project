cmake_minimum_required(VERSION 3.17)
project(project)


# Specify the path to OpenSSL include directory
include_directories("C:/Program Files/OpenSSL-Win64/include")

# Specify the path to OpenSSL library directory
link_directories("C:/Program Files/OpenSSL-Win64/bin")

# Create an executable from your main.cpp file
add_executable(project main.cpp rsa_encryption_decryption/openssl_rsa.cpp rsa_encryption_decryption/openssl_rsa.h rsa_authentication/rsa_auth.h rsa_authentication/rsa_auth.cpp)

# Link against OpenSSL libraries
target_link_libraries(project libssl-3-x64 libcrypto-3-x64)
