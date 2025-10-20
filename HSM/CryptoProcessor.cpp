#include "CryptoProcessor.h"
#include <openssl/err.h>
#include <stdexcept>
#include <iomanip>
#include <sstream>

std::vector<unsigned char> CryptoEngine::generate_key(size_t key_len_bytes) {
    std::vector<unsigned char> key(key_len_bytes);
    if (RAND_bytes(key.data(), key.size()) != 1) {
        throw std::runtime_error("Failed to generate random key");
    }
    return key;
}

std::vector<unsigned char> CryptoEngine::derive_key_from_password(const std::string& password, const std::vector<unsigned char>& salt, int key_len_bytes) {
    std::vector<unsigned char> key(key_len_bytes);
    if (PKCS5_PBKDF2_HMAC(password.c_str(), password.length(),
                          salt.data(), salt.size(), 10000, // 10000 iterations
                          EVP_sha256(), key.size(), key.data()) != 1) {
        throw std::runtime_error("Failed to derive key from password");
    }
    return key;
}

bool CryptoEngine::encrypt_aes_gcm(const std::vector<unsigned char>& plaintext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, std::vector<unsigned char>& ciphertext, std::vector<unsigned char>& tag) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len;
    int ciphertext_len;

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto err;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL)) goto err;
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data())) goto err;

    ciphertext.resize(plaintext.size());
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size())) goto err;
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) goto err;
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);
    
    tag.resize(16); // GCM tag is 16 bytes
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data())) goto err;

    EVP_CIPHER_CTX_free(ctx);
    return true;

err:
    EVP_CIPHER_CTX_free(ctx);
    return false;
}

bool CryptoEngine::decrypt_aes_gcm(const std::vector<unsigned char>& ciphertext, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, const std::vector<unsigned char>& tag, std::vector<unsigned char>& plaintext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    int len;
    int plaintext_len;
    int ret;

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) goto err;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL)) goto err;
    if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv.data())) goto err;
    
    plaintext.resize(ciphertext.size());
    if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size())) goto err;
    plaintext_len = len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), (void*)tag.data())) goto err;

    ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        plaintext_len += len;
        plaintext.resize(plaintext_len);
        return true;
    } else {
        return false;
    }
err:
    EVP_CIPHER_CTX_free(ctx);
    return false;
}

std::vector<unsigned char> CryptoEngine::hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = (unsigned char) strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

std::string CryptoEngine::bytes_to_hex(const std::vector<unsigned char>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char b : bytes) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}