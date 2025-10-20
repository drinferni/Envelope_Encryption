#include "CryptoProcessor.h"
#include <stdexcept>
#include <vector>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/ec.h>      // For EC curve definitions
#include <openssl/obj_mac.h> // For NID_prime256v1

// --- Symmetric Encryption (AES-256-GCM) ---

std::string CryptoEngine::encrypt(const std::string& plaintext, const std::string& key) {
    if (key.length() != 32) throw std::runtime_error("Invalid key size for AES-256.");

    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char ciphertext[plaintext.length() + AES_BLOCK_SIZE];

    // Generate random IV
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        throw std::runtime_error("Failed to generate IV.");
    }

    if (!(ctx = EVP_CIPHER_CTX_new())) throw std::runtime_error("Failed to create cipher context.");

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, (const unsigned char*)key.c_str(), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptInit failed.");
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, (const unsigned char*)plaintext.c_str(), plaintext.length())) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptUpdate failed.");
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EncryptFinal failed.");
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    std::string result(reinterpret_cast<char*>(iv), sizeof(iv));
    result.append(reinterpret_cast<char*>(ciphertext), ciphertext_len);
    return result;
}

std::string CryptoEngine::decrypt(const std::string& ciphertext, const std::string& key) {
    if (key.length() != 32) throw std::runtime_error("Invalid key size for AES-256.");
    if (ciphertext.length() < AES_BLOCK_SIZE) throw std::runtime_error("Invalid ciphertext size.");

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    unsigned char plaintext[ciphertext.length()];
    const unsigned char* iv = (const unsigned char*)ciphertext.c_str();
    const unsigned char* ct = (const unsigned char*)ciphertext.c_str() + AES_BLOCK_SIZE;
    int ct_len = ciphertext.length() - AES_BLOCK_SIZE;

    if (!(ctx = EVP_CIPHER_CTX_new())) throw std::runtime_error("Failed to create cipher context.");

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, (const unsigned char*)key.c_str(), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptInit failed.");
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ct, ct_len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptUpdate failed.");
    }
    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptFinal failed. Tag verification error?");
    }
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return std::string(reinterpret_cast<char*>(plaintext), plaintext_len);
}

// --- Asymmetric Signing & Verification ---

std::string CryptoEngine::sign(const std::string& data, const std::string& privateKeyPem) {
    BIO* bio = BIO_new_mem_buf(privateKeyPem.c_str(), -1);
    EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) throw std::runtime_error("Failed to read private key.");

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create signature context.");
    }

    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("Failed to initialize digest sign.");
    }

    if (EVP_DigestSignUpdate(md_ctx, data.c_str(), data.length()) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("Failed to update digest sign.");
    }
    
    size_t sig_len;
    if (EVP_DigestSignFinal(md_ctx, NULL, &sig_len) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("Failed to get signature length.");
    }
    
    std::vector<unsigned char> signature(sig_len);
    if (EVP_DigestSignFinal(md_ctx, signature.data(), &sig_len) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("Failed to create signature.");
    }

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(md_ctx);
    return std::string(signature.begin(), signature.end());
}


bool CryptoEngine::verify(const std::string& data, const std::string& signature, const std::string& publicKeyPem) {
    BIO* bio = BIO_new_mem_buf(publicKeyPem.c_str(), -1);
    EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!pkey) throw std::runtime_error("Failed to read public key.");

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
     if (!md_ctx) {
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create verification context.");
    }
    
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("Failed to initialize digest verify.");
    }

    if (EVP_DigestVerifyUpdate(md_ctx, data.c_str(), data.length()) <= 0) {
        EVP_PKEY_free(pkey);
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("Failed to update digest verify.");
    }
    
    int result = EVP_DigestVerifyFinal(md_ctx, (const unsigned char*)signature.c_str(), signature.length());

    EVP_PKEY_free(pkey);
    EVP_MD_CTX_free(md_ctx);
    
    return result == 1;
}

// --- Key Generation ---

std::string CryptoEngine::generateAESKey() {
    unsigned char key[32];
    if (RAND_bytes(key, sizeof(key)) != 1) {
        throw std::runtime_error("Failed to generate AES key.");
    }
    return std::string(reinterpret_cast<char*>(key), sizeof(key));
}

std::pair<std::string, std::string> CryptoEngine::generateRSAKeyPair() {
    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (EVP_PKEY_keygen_init(ctx) <= 0) throw std::runtime_error("RSA keygen init failed.");
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096) <= 0) throw std::runtime_error("Failed to set RSA key bits.");
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) throw std::runtime_error("RSA keygen failed.");
    EVP_PKEY_CTX_free(ctx);

    BIO *priv_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL);
    char *priv_key_str;
    long priv_len = BIO_get_mem_data(priv_bio, &priv_key_str);
    std::string priv_key(priv_key_str, priv_len);
    BIO_free(priv_bio);

    BIO *pub_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pub_bio, pkey);
    char *pub_key_str;
    long pub_len = BIO_get_mem_data(pub_bio, &pub_key_str);
    std::string pub_key(pub_key_str, pub_len);
    BIO_free(pub_bio);

    EVP_PKEY_free(pkey);
    return {priv_key, pub_key};
}

std::pair<std::string, std::string> CryptoEngine::generateECKeyPair(const std::string& curveName) {
    int nid = OBJ_txt2nid(curveName.c_str());
    if (nid == NID_undef) {
        throw std::runtime_error("Unknown or unsupported curve name: " + curveName);
    }

    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (EVP_PKEY_keygen_init(ctx) <= 0) throw std::runtime_error("EC keygen init failed.");
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0) throw std::runtime_error("Failed to set EC curve.");
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) throw std::runtime_error("EC keygen failed.");
    EVP_PKEY_CTX_free(ctx);

    BIO *priv_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(priv_bio, pkey, NULL, NULL, 0, NULL, NULL);
    char *priv_key_str;
    long priv_len = BIO_get_mem_data(priv_bio, &priv_key_str);
    std::string priv_key(priv_key_str, priv_len);
    BIO_free(priv_bio);

    BIO *pub_bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pub_bio, pkey);
    char *pub_key_str;
    long pub_len = BIO_get_mem_data(pub_bio, &pub_key_str);
    std::string pub_key(pub_key_str, pub_len);
    BIO_free(pub_bio);

    EVP_PKEY_free(pkey);
    return {priv_key, pub_key};
}

