#include "EnvelopeEncryptionManager.h"
#include "CryptoProcessor.h"
#include <include/json.hpp>
#include <stdexcept>

using json = nlohmann::json;

EnvelopeEncryptionManager::EnvelopeEncryptionManager(KeyVault& vault) : vault_(vault) {}

bool EnvelopeEncryptionManager::encrypt(const std::string& key_id, const std::vector<unsigned char>& plaintext, std::string& out_bundle) {
    KeyMetadata kek_metadata;
    std::vector<unsigned char> kek_plaintext;
    
    // 1. Load the Key Encryption Key (KEK) from the vault
    if (!vault_.load_key(key_id, kek_metadata, kek_plaintext)) {
        return false;
    }
    if (kek_metadata.status != "enabled") {
        return false; // Key is not usable
    }

    // 2. Generate a new Data Encryption Key (DEK)
    auto dek = CryptoEngine::generate_key(32);

    // 3. Encrypt the plaintext with the DEK
    auto data_iv = CryptoEngine::generate_key(12);
    std::vector<unsigned char> data_ciphertext;
    std::vector<unsigned char> data_tag;
    if (!CryptoEngine::encrypt_aes_gcm(plaintext, dek, data_iv, data_ciphertext, data_tag)) {
        return false;
    }

    // 4. Wrap (encrypt) the DEK with the KEK
    auto dek_iv = CryptoEngine::generate_key(12);
    std::vector<unsigned char> wrapped_dek;
    std::vector<unsigned char> dek_tag;
    if (!CryptoEngine::encrypt_aes_gcm(dek, kek_plaintext, dek_iv, wrapped_dek, dek_tag)) {
        return false;
    }

    // 5. Create the output bundle
    json bundle;
    bundle["key_id"] = key_id;
    bundle["wrapped_dek"] = CryptoEngine::bytes_to_hex(wrapped_dek);
    bundle["dek_iv"] = CryptoEngine::bytes_to_hex(dek_iv);
    bundle["dek_tag"] = CryptoEngine::bytes_to_hex(dek_tag);
    bundle["ciphertext"] = CryptoEngine::bytes_to_hex(data_ciphertext);
    bundle["data_iv"] = CryptoEngine::bytes_to_hex(data_iv);
    bundle["data_tag"] = CryptoEngine::bytes_to_hex(data_tag);
    
    out_bundle = bundle.dump();
    return true;
}

bool EnvelopeEncryptionManager::decrypt(const std::string& in_bundle, std::vector<unsigned char>& plaintext) {
    json bundle;
    try {
        bundle = json::parse(in_bundle);
    } catch (json::parse_error& e) {
        return false; // Invalid bundle format
    }

    // 1. Parse the bundle
    std::string key_id = bundle["key_id"];
    auto wrapped_dek = CryptoEngine::hex_to_bytes(bundle["wrapped_dek"]);
    auto dek_iv = CryptoEngine::hex_to_bytes(bundle["dek_iv"]);
    auto dek_tag = CryptoEngine::hex_to_bytes(bundle["dek_tag"]);
    auto data_ciphertext = CryptoEngine::hex_to_bytes(bundle["ciphertext"]);
    auto data_iv = CryptoEngine::hex_to_bytes(bundle["data_iv"]);
    auto data_tag = CryptoEngine::hex_to_bytes(bundle["data_tag"]);

    // 2. Load the KEK from the vault
    KeyMetadata kek_metadata;
    std::vector<unsigned char> kek_plaintext;
    if (!vault_.load_key(key_id, kek_metadata, kek_plaintext)) {
        return false;
    }
    if (kek_metadata.status != "enabled") {
        return false; // Key is not usable
    }

    // 3. Unwrap (decrypt) the DEK with the KEK
    std::vector<unsigned char> dek;
    if (!CryptoEngine::decrypt_aes_gcm(wrapped_dek, kek_plaintext, dek_iv, dek_tag, dek)) {
        return false; // Failed to unwrap DEK, likely invalid tag or key
    }
    
    // 4. Decrypt the ciphertext with the DEK
    if (!CryptoEngine::decrypt_aes_gcm(data_ciphertext, dek, data_iv, data_tag, plaintext)) {
        return false; // Failed to decrypt data
    }
    
    return true;
}