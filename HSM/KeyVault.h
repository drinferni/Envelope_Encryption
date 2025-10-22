#ifndef KEY_VAULT_H
#define KEY_VAULT_H

#include <string>
#include <map>
#include <vector>

struct KeyData {
    std::string keyName;    // The name of the key (e.g., "MyPersonalAESKey")
    std::string algorithm;
    std::string privateKey; // For private keys or symmetric keys (like AES)
    std::string publicKey;  // For public keys (empty for AES)
};


class KeyVault {
public:
    KeyVault(const std::string& storagePath);
    bool createKey(const std::string& keyName, const std::string& algorithm);
    KeyData getKey(const std::string& keyName) const;
    void printKey(const std::string& keyName);
    void zeroizeAllKeys();

private:
    std::string storagePath;
    KeyData loadKeyFromFile(const std::string& path) const;
    void saveKeyToFile(const std::string& path, const KeyData& keyData);
    std::string readFileContent(const std::string &path) const;
};

#endif // KEY_VAULT_H

