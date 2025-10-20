#ifndef CRYPTO_ENGINE_H
#define CRYPTO_ENGINE_H

#include <vector>
#include <string>
#include <memory>
#include <openssl/evp.h>
#include <openssl/rand.h>

class CryptoEngine {
public:
    // Generate a random key (e.g., for AES)
    static std::vector<unsigned char> generate_key(size_t key_len_bytes);

    // Generate a key from a password using PBKDF2
    static std::vector<unsigned char> derive_key_from_password(const std::string& password, const std::vector<unsigned char>& salt, int key_len_bytes);

    // AES-256-GCM Encryption
    static bool encrypt_aes_gcm(const std::vector<unsigned char>& plaintext,
                                const std::vector<unsigned char>& key,
                                const std::vector<unsigned char>& iv,
                                std::vector<unsigned char>& ciphertext,
                                std::vector<unsigned char>& tag);

    // AES-256-GCM Decryption
    static bool decrypt_aes_gcm(const std::vector<unsigned char>& ciphertext,
                                const std::vector<unsigned char>& key,
                                const std::vector<unsigned char>& iv,
                                const std::vector<unsigned char>& tag,
                                std::vector<unsigned char>& plaintext);

    // Utility to convert hex strings to bytes
    static std::vector<unsigned char> hex_to_bytes(const std::string& hex);
    
    // Utility to convert bytes to hex strings
    static std::string bytes_to_hex(const std::vector<unsigned char>& bytes);
};

#endif // CRYPTO_ENGINE_H