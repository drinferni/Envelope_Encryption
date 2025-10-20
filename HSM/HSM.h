#ifndef HSM_H
#define HSM_H

#include <string>
#include "AccessController.h"
#include "KeyVault.h"
#include "CryptoProcessor.h"

class IntegrityMonitor {
public:
    void trigger(KeyVault& vault) {
        // In a real HSM, this would be a hardware-level action.
        // Here, we simulate it by securely deleting all keys.
        vault.zeroizeAllKeys();
    }
};

class HSM {
public:
    HSM(const std::string& passwordFile, const std::string& userFile, const std::string& keyStorePath);

    bool createKey(const std::string& username, const std::string& password, const std::string& keyName, const std::string& algorithm);
    std::string encrypt(const std::string& username, const std::string& password, const std::string& keyName, const std::string& plaintext);
    std::string decrypt(const std::string& username, const std::string& password, const std::string& keyName, const std::string& ciphertext);
    std::string sign(const std::string& username, const std::string& password, const std::string& keyName, const std::string& data);
    bool verify(const std::string& username, const std::string& password, const std::string& keyName, const std::string& data, const std::string& signature);

    void triggerTamperEvent();

private:
    AccessController accessController;
    KeyVault keyVault;
    CryptoEngine cryptoEngine;
    IntegrityMonitor integrityMonitor;
};

#endif // HSM_H

