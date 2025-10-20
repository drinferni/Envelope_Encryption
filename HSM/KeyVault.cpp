#include "KeyVault.h"
#include "CryptoProcessor.h"
#include <fstream>
#include <stdexcept>
#include <chrono>

// JSON serialization for KeyMetadata
void to_json(json& j, const KeyMetadata& m) {
    j = json{{"key_id", m.key_id}, {"version", m.version}, {"algorithm", m.algorithm}, {"status", m.status}, {"creation_date", m.creation_date}};
}
void from_json(const json& j, KeyMetadata& m) {
    j.at("key_id").get_to(m.key_id);
    j.at("version").get_to(m.version);
    j.at("algorithm").get_to(m.algorithm);
    j.at("status").get_to(m.status);
    j.at("creation_date").get_to(m.creation_date);
}

KeyVault::KeyVault(const std::string& vault_path, const std::string& master_password) : vault_path_(vault_path) {
    // A fixed salt is insecure for production, but simple for this example.
    // In a real system, this should be stored securely.
    std::vector<unsigned char> salt = {'s', 'a', 'l', 't', 'y', 's', 'a', 'l', 't'};
    master_key_ = CryptoEngine::derive_key_from_password(master_password, salt, 32); // 32 bytes for AES-256
}

bool KeyVault::store_key(const KeyMetadata& metadata, const std::vector<unsigned char>& plaintext_key) {
    // 1. Encrypt the key material with the master key
    auto iv = CryptoEngine::generate_key(12); // GCM recommended IV size
    std::vector<unsigned char> ciphertext;
    std::vector<unsigned char> tag;

    if (!CryptoEngine::encrypt_aes_gcm(plaintext_key, master_key_, iv, ciphertext, tag)) {
        return false;
    }

    // 2. Create a JSON object to store the wrapped key and metadata
    json key_file_content;
    key_file_content["metadata"] = metadata;
    key_file_content["iv"] = CryptoEngine::bytes_to_hex(iv);
    key_file_content["tag"] = CryptoEngine::bytes_to_hex(tag);
    key_file_content["ciphertext"] = CryptoEngine::bytes_to_hex(ciphertext);

    // 3. Write to file
    std::ofstream ofs(vault_path_ + "/" + metadata.key_id + ".json");
    if (!ofs.is_open()) return false;
    ofs << key_file_content.dump(4);
    return true;
}

bool KeyVault::load_key(const std::string& key_id, KeyMetadata& metadata, std::vector<unsigned char>& plaintext_key) {
    // 1. Read the key file
    std::ifstream ifs(vault_path_ + "/" + key_id + ".json");
    if (!ifs.is_open()) return false;
    json key_file_content;
    ifs >> key_file_content;
    
    // 2. Parse the content
    metadata = key_file_content["metadata"].get<KeyMetadata>();
    auto iv = CryptoEngine::hex_to_bytes(key_file_content["iv"]);
    auto tag = CryptoEngine::hex_to_bytes(key_file_content["tag"]);
    auto ciphertext = CryptoEngine::hex_to_bytes(key_file_content["ciphertext"]);

    // 3. Decrypt the key material with the master key
    if (!CryptoEngine::decrypt_aes_gcm(ciphertext, master_key_, iv, tag, plaintext_key)) {
        return false;
    }

    return true;
}

bool KeyVault::key_exists(const std::string& key_id) const {
    std::ifstream f(vault_path_ + "/" + key_id + ".json");
    return f.good();
}

bool KeyVault::update_metadata(const KeyMetadata& metadata) {
    std::vector<unsigned char> plaintext_key;
    KeyMetadata old_metadata;
    if (!load_key(metadata.key_id, old_metadata, plaintext_key)) {
        return false;
    }
    // Now store it again with the new metadata
    return store_key(metadata, plaintext_key);
}