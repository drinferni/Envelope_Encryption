#include "KeyVault.h"
#include "CryptoProcessor.h"
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <ctime>
#include <filesystem>

namespace fs = std::filesystem;

KeyVault::KeyVault(const std::string& storagePath) : storagePath(storagePath) {}

bool KeyVault::createKey(const std::string& keyName, const std::string& algorithm) {
    if (keyName.empty() || keyName.find("..") != std::string::npos) {
        return false; // Invalid key name
    }

    std::string path = storagePath + "/" + keyName;
    if (fs::exists(path)) {
        return false; // Key already exists
    }

    KeyData keyData;
    keyData.algorithm = algorithm;

    if (algorithm == "AES") {
        keyData.privateKey = CryptoEngine::generateAESKey();
    } else if (algorithm == "RSA") {
        auto keyPair = CryptoEngine::generateRSAKeyPair();
        keyData.privateKey = keyPair.first;
        keyData.publicKey = keyPair.second;
    } else if (algorithm == "EC") {
        auto keyPair = CryptoEngine::generateECKeyPair();
        keyData.privateKey = keyPair.first;
        keyData.publicKey = keyPair.second;
    } else {
        return false; // Unsupported algorithm
    }
    
    time_t now = time(0);
    keyData.metadata["creation_date"] = ctime(&now);
    keyData.metadata["state"] = "enabled";
    
    saveKeyToFile(path, keyData);
    return true;
}

KeyData KeyVault::getKey(const std::string& keyName) const {
    std::string path = storagePath + "/" + keyName;
    if (!fs::exists(path)) {
        throw std::runtime_error("Key not found.");
    }
    return loadKeyFromFile(path);
}

void KeyVault::saveKeyToFile(const std::string& path, const KeyData& keyData) {
    std::ofstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open key file for writing: " + path);
    }
    file << "algorithm:" << keyData.algorithm << std::endl;
    for (const auto& pair : keyData.metadata) {
        file << pair.first << ":" << pair.second; // ctime includes a newline
    }
    file << "---PRIVATE_KEY---" << std::endl;
    file << keyData.privateKey << std::endl;
    if (!keyData.publicKey.empty()) {
        file << "---PUBLIC_KEY---" << std::endl;
        file << keyData.publicKey << std::endl;
    }
}

KeyData KeyVault::loadKeyFromFile(const std::string& path) const {
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open key file for reading: " + path);
    }

    KeyData keyData;
    std::string line;
    std::string* current_key_buffer = nullptr;

    while (std::getline(file, line)) {
        if (line.rfind("algorithm:", 0) == 0) {
            keyData.algorithm = line.substr(10);
        } else if (line.rfind("creation_date:", 0) == 0) {
            keyData.metadata["creation_date"] = line.substr(14) + "\n";
        } else if (line.rfind("state:", 0) == 0) {
            keyData.metadata["state"] = line.substr(6);
        } else if (line == "---PRIVATE_KEY---") {
            current_key_buffer = &keyData.privateKey;
            keyData.privateKey.clear();
        } else if (line == "---PUBLIC_KEY---") {
            current_key_buffer = &keyData.publicKey;
            keyData.publicKey.clear();
        } else if (current_key_buffer) {
            *current_key_buffer += line + "\n";
        }
    }
    return keyData;
}


void KeyVault::zeroizeAllKeys() {
    for (const auto& entry : fs::directory_iterator(storagePath)) {
        fs::remove(entry.path());
    }
}

