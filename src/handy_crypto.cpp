/*
 * Copyright (c) 2023 Cesar Ruano
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
 
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>

#include "handy_crypto.hpp"

namespace Handy_crypto{

    std::vector<unsigned char> sign(const std::string& private_key_str, 
                                    const std::string& message) {
        EVP_PKEY *pkey = nullptr;
        BIO *bio = BIO_new_mem_buf(private_key_str.c_str(), -1);

        if (!bio) {
            std::cerr << "Error creating buffer for private key.\n";
            return {};
        }

        pkey = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);

        if (!pkey) {
            std::cerr << "Error reading the private key.\n";
            return {};
        }

        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (!mdctx) {
            std::cerr << "Failed to create message digest context.\n";
            EVP_PKEY_free(pkey);
            return {};
        }

        if (EVP_SignInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
            std::cerr << "Failed to initialize signing process.\n";
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return {};
        }

        if (EVP_SignUpdate(mdctx, message.data(), message.size()) != 1) {
            std::cerr << "Failed to update signing context.\n";
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return {};
        }

        std::vector<unsigned char> signature(EVP_PKEY_size(pkey));
        unsigned int siglen;

        if (EVP_SignFinal(mdctx, signature.data(), &siglen, pkey) != 1) {
            std::cerr << "Failed to finalize signing process.\n";
            EVP_MD_CTX_free(mdctx);
            EVP_PKEY_free(pkey);
            return {};
        }

        signature.resize(siglen);

        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);

        return signature;
    }

    bool verify(const std::string& public_key_str, 
                const std::string& message, 
                std::vector<unsigned char> signature) {
                    
        EVP_PKEY *pkey = nullptr;
        BIO *bio = BIO_new_mem_buf(public_key_str.c_str(), -1);
        if (bio == nullptr) return false;

        pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
        BIO_free(bio);
        if (pkey == nullptr) return false;

        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_VerifyInit_ex(mdctx, EVP_sha256(), nullptr);
        EVP_VerifyUpdate(mdctx, message.data(), message.size());

        int result = EVP_VerifyFinal(mdctx, signature.data(), signature.size(), pkey);

        EVP_MD_CTX_free(mdctx);
        EVP_PKEY_free(pkey);

        return result == 1;
    }

    std::vector<unsigned char> encrypt_data(const std::string& data, 
                                            const unsigned char* aes_encryption_key, 
                                            const unsigned char* aes_encryption_iv) {
        std::vector<unsigned char> encrypted_data;

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aes_encryption_key, aes_encryption_iv);

        // Calculate the buffer size for the ciphertext
        int ciphertext_len = data.size() + AES_BLOCK_SIZE;
        encrypted_data.resize(ciphertext_len);

        // Perform the encryption
        int len;
        EVP_EncryptUpdate(ctx, encrypted_data.data(), &len, reinterpret_cast<const unsigned char*>(data.c_str()), data.size());
        ciphertext_len = len;

        // Finalize the encryption
        EVP_EncryptFinal_ex(ctx, encrypted_data.data() + len, &len);
        ciphertext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        // Resize the vector to match the actual ciphertext size
        encrypted_data.resize(ciphertext_len);

        return encrypted_data;
    }

    std::string decrypt_data(const std::vector<unsigned char>& encrypted_data, 
                             const unsigned char* aes_encryption_key, 
                             const unsigned char* aes_encryption_iv) {
        std::string decrypted_data;

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, aes_encryption_key, aes_encryption_iv);

        // Calculate the buffer size for the plaintext
        int plaintext_len = encrypted_data.size();
        std::vector<unsigned char> decrypted_buffer(plaintext_len);

        // Perform the decryption
        int len;
        EVP_DecryptUpdate(ctx, decrypted_buffer.data(), &len, encrypted_data.data(), plaintext_len);
        plaintext_len = len;

        // Finalize the decryption
        EVP_DecryptFinal_ex(ctx, decrypted_buffer.data() + len, &len);
        plaintext_len += len;

        EVP_CIPHER_CTX_free(ctx);

        // Resize the vector to match the actual plaintext size
        decrypted_buffer.resize(plaintext_len);

        decrypted_data.assign(decrypted_buffer.begin(), decrypted_buffer.end());

        return decrypted_data;
    }

    void write_data_and_signature_to_file(const std::string& filename, 
                                          const std::string& data, 
                                          const std::vector<unsigned char>& signature,
                                          const unsigned char* aes_encryption_key, 
                                          const unsigned char* aes_encryption_iv) {
        // Encrypt the data
        std::vector<unsigned char> encrypted_data = encrypt_data(data,
                                                                 aes_encryption_key,
                                                                 aes_encryption_iv);

        // Write the encrypted data and signature to the file
        std::ofstream file(filename, std::ios::binary);
        file.write(reinterpret_cast<const char*>(encrypted_data.data()), encrypted_data.size());
        file.write(reinterpret_cast<const char*>(signature.data()), signature.size());
        
        // Close the file explicitly
        file.close();
    }

    void extract_data_and_signature_from_file(const std::string& filename, 
                                              std::string& data, 
                                              std::vector<unsigned char>& signature,
                                              const unsigned char* aes_encryption_key, 
                                              const unsigned char* aes_encryption_iv) {
                                                  
        std::ifstream file(filename, std::ios::binary | std::ios::ate);
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        // Assuming the signature size is fixed, you may adjust this according to your signature algorithm
        size_t signature_size = 256; 

        // Read the encrypted data
        std::vector<char> encrypted_data_buffer(size - signature_size);
        file.read(encrypted_data_buffer.data(), encrypted_data_buffer.size());
        std::vector<unsigned char> encrypted_data(encrypted_data_buffer.begin(), encrypted_data_buffer.end());

        // Decrypt the data
        data = decrypt_data(encrypted_data,
                            aes_encryption_key,
                            aes_encryption_iv);

        // Read the signature
        signature.resize(signature_size);
        file.read(reinterpret_cast<char*>(signature.data()), signature.size());
        
        // Close the file explicitly
        file.close();
    }
}