#ifndef KEY_VAULT_H
#define KEY_VAULT_H

#include <string>
#include <vector>
#include <map>
#include <include/json.hpp>

using json = nlohmann::json;

// Represents a key's metadata
struct KeyMetadata {
    std::string key_id;
    int version;
    std::string algorithm;
    std::string status; // "enabled", "disabled", "destroyed"
    long long creation_date;
};

void to_json(json& j, const KeyMetadata& m);
void from_json(const json& j, KeyMetadata& m);

class KeyVault {
public:
    KeyVault(const std::string& vault_path, const std::string& master_password);

    // Store a key encrypted by the master key
    bool store_key(const KeyMetadata& metadata, const std::vector<unsigned char>& plaintext_key);

    // Load a key, decrypting it with the master key
    bool load_key(const std::string& key_id, KeyMetadata& metadata, std::vector<unsigned char>& plaintext_key);

    // Check if a key exists
    bool key_exists(const std::string& key_id) const;

    // Update the metadata for a key
    bool update_metadata(const KeyMetadata& metadata);

private:
    std::string vault_path_;
    std::vector<unsigned char> master_key_;
};

#endif // KEY_VAULT_H