#include "handy_crypto.hpp"
#include <string>
#include <vector>
#include <iostream>

#include "public_key.h"
#include "private_key.h"
#include "aes_key.h"

using namespace::Handy_crypto;

int test_encryption(void){
    std::cout << "***************************************************" << std::endl;
    std::cout << "Test the cryptography functions" << std::endl;
    
    const std::string message = "This is a test_encryption message.";

    // Sign the message
    std::vector<unsigned char> signature = sign(private_key, message);
    if (signature.empty()) {
        std::cerr << "Signing failed.\n";
        return 1;
    }

    // Encrypt the message
    std::vector<unsigned char> encrypted_data = encrypt_data(message, aes_encryption_key, aes_encryption_iv);
    if (encrypted_data.empty()) {
        std::cerr << "Encryption failed.\n";
        return 1;
    }

    // Decrypt the message
    std::string decrypted_data = decrypt_data(encrypted_data, aes_encryption_key, aes_encryption_iv);
    if (decrypted_data.empty()) {
        std::cerr << "Decryption failed.\n";
        return 1;
    }

    // Verify the signature
    bool verification_status = verify(public_key, decrypted_data, signature);
    if (!verification_status) {
        std::cerr << "Signature verification failed.\n";
        return 1;
    }

    std::cout << "Original message: " << message << "\n";
    std::cout << "Decrypted message: " << decrypted_data << "\n";
    std::cout << "Signature verification: success\n";
    
    return 0;
}

int test_signed_file(void){
    std::cout << "***************************************************"<<std::endl;
    std::cout << "Test the self contained signed file" << std::endl;
    
    const std::string message = "This is a test_signed_file message.";
    const std::string file_path = "./encrypted_and_signed_file.aes";

    // Sign the message
    std::vector<unsigned char> signature = sign(private_key, message);
    if (signature.empty()) {
        std::cerr << "Signing failed.\n";
        return 1;
    }
    // Write to file
    write_data_and_signature_to_file(file_path, 
                                     message, 
                                     signature,
                                     aes_encryption_key, 
                                     aes_encryption_iv);
    // Read back the file
    std::string read_data;
    std::vector<unsigned char> read_signature;
    extract_data_and_signature_from_file(file_path, 
                                         read_data, 
                                         read_signature,
                                         aes_encryption_key, 
                                         aes_encryption_iv);
                                     
    // Verify the signature
    bool verification_status = verify(public_key, read_data, read_signature);
    if (!verification_status) {
        std::cerr << "Signature verification failed.\n";
        return 1;
    }
    
    std::cout << "Original message: " << message << "\n";
    std::cout << "Decrypted message: " << read_data << "\n";
    std::cout << "Signature verification: success\n";
    
    return 0;
}

int main() {
    
    test_encryption();   
    
    std::cout << std::endl;
    
    test_signed_file();

    return 0;
}
