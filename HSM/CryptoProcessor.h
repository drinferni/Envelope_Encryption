#ifndef CRYPTO_ENGINE_H
#define CRYPTO_ENGINE_H

#include <string>
#include <utility> // For std::pair
#include <openssl/obj_mac.h> // For NID definitions

class CryptoEngine {
public:
    // Symmetric encryption
    std::string encrypt(const std::string& plaintext, const std::string& key);
    std::string decrypt(const std::string& ciphertext, const std::string& key);

    // Asymmetric signing and verification
    std::string sign(const std::string& data, const std::string& privateKeyPem);
    bool verify(const std::string& data, const std::string& signature, const std::string& publicKeyPem);

    // Key Generation
    static std::string generateAESKey();
    static std::pair<std::string, std::string> generateRSAKeyPair();
    static std::pair<std::string, std::string> generateECKeyPair(const std::string& curveName = "secp256k1");
};

#endif // CRYPTO_ENGINE_H

