#ifndef KEY_VAULT_H
#define KEY_VAULT_H

#include <string>
#include <map>
#include <vector>

struct KeyData {
    std::string algorithm;
    std::string privateKey; // For private keys or symmetric keys
    std::string publicKey;  // For public keys
    std::map<std::string, std::string> metadata;
};

class KeyVault {
public:
    KeyVault(const std::string& storagePath);
    bool createKey(const std::string& keyName, const std::string& algorithm);
    KeyData getKey(const std::string& keyName) const;
    void zeroizeAllKeys();

private:
    std::string storagePath;
    KeyData loadKeyFromFile(const std::string& path) const;
    void saveKeyToFile(const std::string& path, const KeyData& keyData);
};

#endif // KEY_VAULT_H

