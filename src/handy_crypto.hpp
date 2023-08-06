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
 
#ifndef __HANDY_CRYPTO_LIB_H__
#define __HANDY_CRYPTO_LIB_H__

#define HANDY_CRYPTO_MAJOR_VERSION 1
#define HANDY_CRYPTO_MINOR_VERSION 0
#define HANDY_CRYPTO_PATCH_VERSION 0

#include <vector>
#include <string>

namespace Handy_crypto{

    std::vector<unsigned char> sign(const std::string& private_key_str, 
                                    const std::string& message);

    bool verify(const std::string& public_key_str, 
                const std::string& message, 
                std::vector<unsigned char> signature);

    std::vector<unsigned char> encrypt_data(const std::string& data, 
                                            const unsigned char* aes_encryption_key, 
                                            const unsigned char* aes_encryption_iv);

    std::string decrypt_data(const std::vector<unsigned char>& encrypted_data, 
                             const unsigned char* aes_encryption_key, 
                             const unsigned char* aes_encryption_iv);
                             
    void write_data_and_signature_to_file(const std::string& filename, 
                                          const std::string& data, 
                                          const std::vector<unsigned char>& signature,
                                          const unsigned char* aes_encryption_key, 
                                          const unsigned char* aes_encryption_iv);

    void extract_data_and_signature_from_file(const std::string& filename, 
                                              std::string& data, 
                                              std::vector<unsigned char>& signature,
                                              const unsigned char* aes_encryption_key, 
                                              const unsigned char* aes_encryption_iv);
}
                                          
#endif
