#ifndef CRYPTO_ENGINE_H
#define CRYPTO_ENGINE_H

#include <string>
#include <utility> // For std::pair
#include <openssl/obj_mac.h> // For NID definitions

class CryptoEngine {
public:
    // Key Generation
    static std::string generateAESKey();
    static std::pair<std::string, std::string> generateRSAKeyPair();
    static std::pair<std::string, std::string> generateECKeyPair(const std::string& curveName = "secp256k1");
};

#endif // CRYPTO_ENGINE_H

