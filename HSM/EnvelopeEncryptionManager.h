#ifndef ENVELOPE_ENCRYPTION_MANAGER_H
#define ENVELOPE_ENCRYPTION_MANAGER_H

#include "KeyVault.h"
#include <string>
#include <vector>

class EnvelopeEncryptionManager {
public:
    EnvelopeEncryptionManager(KeyVault& vault);

    // Encrypt data using a key from the vault
    bool encrypt(const std::string& key_id, const std::vector<unsigned char>& plaintext, std::string& out_bundle);

    // Decrypt data from a bundle
    bool decrypt(const std::string& in_bundle, std::vector<unsigned char>& plaintext);

private:
    KeyVault& vault_;
};

#endif // ENVELOPE_ENCRYPTION_MANAGER_H