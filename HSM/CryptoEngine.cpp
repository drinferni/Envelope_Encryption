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
#include <iostream>

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

