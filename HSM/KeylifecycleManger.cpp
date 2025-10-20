#include "KeylifecycleManager.h"
#include "CryptoProcessor.h"
#include <chrono>
#include <stdexcept>

KeyLifecycleManager::KeyLifecycleManager(KeyVault& vault) : vault_(vault) {}

bool KeyLifecycleManager::create_key(const std::string& key_id, const std::string& algorithm) {
    if (vault_.key_exists(key_id)) {
        // For simplicity, we don't allow overwriting.
        // A real implementation would handle versioning.
        return false; 
    }

    size_t key_size_bytes = 0;
    if (algorithm == "AES-256-GCM") {
        key_size_bytes = 32;
    } else {
        throw std::runtime_error("Unsupported algorithm");
    }

    auto plaintext_key = CryptoEngine::generate_key(key_size_bytes);
    
    KeyMetadata metadata;
    metadata.key_id = key_id;
    metadata.version = 1;
    metadata.algorithm = algorithm;
    metadata.status = "enabled";
    metadata.creation_date = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

    return vault_.store_key(metadata, plaintext_key);
}

bool KeyLifecycleManager::rotate_key(const std::string& key_id) {
    KeyMetadata old_metadata;
    std::vector<unsigned char> old_key;
    if (!vault_.load_key(key_id, old_metadata, old_key)) {
        return false;
    }

    // A real rotation would archive the old key. Here we just replace it.
    size_t key_size_bytes = 32; // Assuming AES-256
    auto new_plaintext_key = CryptoEngine::generate_key(key_size_bytes);
    
    KeyMetadata new_metadata = old_metadata;
    new_metadata.version += 1;
    new_metadata.creation_date = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    
    return vault_.store_key(new_metadata, new_plaintext_key);
}

bool KeyLifecycleManager::disable_key(const std::string& key_id) {
    KeyMetadata metadata;
    std::vector<unsigned char> key;
    if (!vault_.load_key(key_id, metadata, key)) {
        return false;
    }
    metadata.status = "disabled";
    return vault_.update_metadata(metadata);
}