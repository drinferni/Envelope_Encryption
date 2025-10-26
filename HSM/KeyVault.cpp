#include "KeyVault.h"
#include <iostream>
#include <fstream>      // For file I/O (std::ifstream, std::ofstream)
#include <sstream>      // For string streams (std::stringstream)
#include <filesystem>   // For directory and file operations (C++17)
#include <iomanip>      // For std::setw, std::hex, std::setfill

// --- OpenSSL Includes ---
// We use the modern EVP (Envelope) API for key generation
#include <openssl/evp.h>
#include <openssl/pem.h>     // For writing keys to PEM format
#include <openssl/bio.h>     // For in-memory I/O
#include <openssl/rand.h>    // For generating AES key
#include <openssl/err.h>     // For error reporting
// --- End OpenSSL Includes ---


// Make filesystem namespace easier to use
namespace fs = std::filesystem;


/**
 * @brief Helper function to read a file's entire content into a string.
 */
std::string KeyVault::readFileContent(const std::string& path) const {
    std::ifstream file(path);
    if (!file) {
        std::cerr << "Error: Could not open file " << path << std::endl;
        return "";
    }
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

/**
 * @brief Saves key data to a specific key directory.
 * This function writes the metadata.txt and the key files.
 */
void KeyVault::saveKeyToFile(const std::string& path, const KeyData& keyData) {
    // 1. Write metadata file
    std::ofstream metaFile(fs::path(path) / "metadata.txt");
    if (!metaFile) {
        std::cerr << "Error: Could not create metadata file in " << path << std::endl;
        return;
    }
    // Format: keyName,algorithm,parentKey
    metaFile << keyData.keyName << "," << keyData.algorithm << "," << keyData.parentKey;
    metaFile.close();

    // 2. Write key files based on algorithm
    if (keyData.algorithm == "AES") {
        std::ofstream keyFile(fs::path(path) / "key.txt");
        if (keyFile) {
            keyFile << keyData.publicKey;
            keyFile.close();
        } else {
            std::cerr << "Error: Could not create key file in " << path << std::endl;
        }
    } else if (keyData.algorithm == "RSA" || keyData.algorithm == "EC") {
        // Write private key
        std::ofstream privFile(fs::path(path) / "private.key");
        if (privFile) {
            privFile << keyData.privateKey;
            privFile.close();
        } else {
            std::cerr << "Error: Could not create private.key file in " << path << std::endl;
        }

        // Write public key
        std::ofstream pubFile(fs::path(path) / "public.key");
        if (pubFile) {
            pubFile << keyData.publicKey;
            pubFile.close();
        } else {
            std::cerr << "Error: Could not create public.key file in " << path << std::endl;
        }
    }
}

/**
 * @brief Loads key data from a specific key directory.
 * This function reads the metadata.txt and the key files.
 */
KeyData KeyVault::loadKeyFromFile(const std::string& path) const {
    KeyData keyData;
    std::string metadataPath = fs::path(path) / "metadata.txt";

    // 1. Read metadata
    std::ifstream metaFile(metadataPath);
    if (!metaFile) {
        std::cerr << "Error: Could not open metadata file at " << metadataPath << std::endl;
        return keyData; // Return empty struct
    }

    std::string line;
    std::getline(metaFile, line);
    std::stringstream ss(line);
    
    // Parse the "name,algo,parentKey" format
    std::getline(ss, keyData.keyName, ',');
    std::getline(ss, keyData.algorithm, ',');
    std::getline(ss, keyData.parentKey, ','); 
    
    metaFile.close();

    // 2. Read key files based on algorithm
    if (keyData.algorithm == "AES") {
        keyData.publicKey = readFileContent(fs::path(path) / "key.txt");
    } else if (keyData.algorithm == "RSA" || keyData.algorithm == "EC") {
        keyData.privateKey = readFileContent(fs::path(path) / "private.key");
        keyData.publicKey = readFileContent(fs::path(path) / "public.key");
    }

    return keyData;
}

/**
 * @brief Constructs a KeyVault, creating the main storage directory if needed.
 */
KeyVault::KeyVault(const std::string& storagePath) : storagePath(storagePath) {
    try {
        // This will create the directory if it doesn't exist.
        fs::create_directory(this->storagePath);
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Error creating storage directory " << this->storagePath 
                  << ": " << e.what() << std::endl;
    }
    // Load or create the master key
    initializeMasterKey();
}

/**
 * @brief Loads the master key from master_key.key, or creates one
 * if it doesn't exist.
 */
void KeyVault::initializeMasterKey() {
    fs::path masterKeyPath = fs::path(storagePath) / "master_key.key";

    if (fs::exists(masterKeyPath)) {
        // Key exists, load it
        this->masterKey = readFileContent(masterKeyPath.string());
        
        if (this->masterKey.empty()) {
            std::cerr << "Warning: Master key file " << masterKeyPath 
                      << " exists but is empty. Generating a new one." << std::endl;
            // If file is empty, fall through to generation logic
        } else {
            std::cout << "Loaded existing master key from " << masterKeyPath << std::endl;
            return; // Successfully loaded
        }
    }

    // If we're here, the key doesn't exist or was empty. Create a new one.
    std::cout << "Generating new master key..." << std::endl;
    this->masterKey = generateAESKey();

    if (this->masterKey.empty()) {
        std::cerr << "FATAL ERROR: Could not generate master key!" << std::endl;
        // In a real app, you might want to throw an exception here
        return;
    }

    std::ofstream keyFile(masterKeyPath);
    if (keyFile) {
        keyFile << this->masterKey;
        keyFile.close();
        std::cout << "Saved new master key to " << masterKeyPath << std::endl;
    } else {
        std::cerr << "FATAL ERROR: Could not write master key to " << masterKeyPath << std::endl;
    }
}

/**
 * @brief Returns the master AES key.
 */
std::string KeyVault::getMasterKey() const {
    std::cout << "getting Master Key" << std::endl;
    return this->masterKey;
}

/**
 * @brief Creates a new key, storing it in its own subdirectory.
 */
bool KeyVault::createKey(const std::string& keyName, const std::string& algorithm, const std::string& parentKeyName) {
    std::cout << "Creating Key :" << keyName << std::endl;
    fs::path keyPath = fs::path(storagePath) / keyName;

    // Check for duplicates
    if (fs::exists(keyPath)) {
        std::cerr << "Error: Key folder '" << keyName << "' already exists." << std::endl;
        return false;
    }

    try {
        // Create the specific folder for this key
        fs::create_directory(keyPath);
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Error creating key directory " << keyPath 
                  << ": " << e.what() << std::endl;
        return false;
    }

    KeyData newKey;
    newKey.algorithm = algorithm;
    newKey.keyName = keyName; 
    newKey.parentKey = parentKeyName; // Set the parent key name

    // --- Real Key Generation using OpenSSL ---
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    if (algorithm == "AES") {
        newKey.publicKey = generateAESKey();
        if (newKey.publicKey.empty()) {
            std::cerr << "Error: AES key generation failed for " << keyName << std::endl;
            fs::remove_all(keyPath); // Clean up empty folder
            return false;
        }
        // publicKey remains empty for symmetric key

    } else if (algorithm == "RSA") {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!ctx) {
            std::cerr << "Error: OpenSSL EVP_PKEY_CTX_new_id failed for RSA." << std::endl;
            fs::remove_all(keyPath); return false;
        }
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            std::cerr << "Error: OpenSSL EVP_PKEY_keygen_init failed for RSA." << std::endl;
            EVP_PKEY_CTX_free(ctx); fs::remove_all(keyPath); return false;
        }
        // Set RSA key bits to 2048
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
            std::cerr << "Error: OpenSSL EVP_PKEY_CTX_set_rsa_keygen_bits failed." << std::endl;
            EVP_PKEY_CTX_free(ctx); fs::remove_all(keyPath); return false;
        }
        
        // Generate the key
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            std::cerr << "Error: OpenSSL EVP_PKEY_keygen failed for RSA." << std::endl;
            EVP_PKEY_CTX_free(ctx); fs::remove_all(keyPath); return false;
        }

        EVP_PKEY_CTX_free(ctx);

    } else if (algorithm == "EC") {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
         if (!ctx) {
            std::cerr << "Error: OpenSSL EVP_PKEY_CTX_new_id failed for EC." << std::endl;
            fs::remove_all(keyPath); return false;
        }
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            std::cerr << "Error: OpenSSL EVP_PKEY_keygen_init failed for EC." << std::endl;
            EVP_PKEY_CTX_free(ctx); fs::remove_all(keyPath); return false;
        }
        // Set EC curve to prime256v1 (NIST P-256)
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
            std::cerr << "Error: OpenSSL EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed." << std::endl;
            EVP_PKEY_CTX_free(ctx); fs::remove_all(keyPath); return false;
        }

        // Generate the key
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            std::cerr << "Error: OpenSSL EVP_PKEY_keygen failed for EC." << std::endl;
            EVP_PKEY_CTX_free(ctx); fs::remove_all(keyPath); return false;
        }

        EVP_PKEY_CTX_free(ctx);

    } else {
        std::cerr << "Error: Unknown algorithm '" << algorithm << "'." << std::endl;
        fs::remove_all(keyPath);
        return false;
    }

    // For RSA and EC, serialize the generated pkey object to strings
    if (algorithm == "RSA" || algorithm == "EC") {
        newKey.privateKey = pkeyToString_private(pkey);
        newKey.publicKey = pkeyToString_public(pkey);
        EVP_PKEY_free(pkey); // Free the key object

        if (newKey.privateKey.empty() || newKey.publicKey.empty()) {
            std::cerr << "Error: Key string serialization failed for " << keyName << std::endl;
            fs::remove_all(keyPath);
            return false;
        }
    }
    // --- End Real Key Generation ---

    // Save the new key data to files
    saveKeyToFile(keyPath.string(), newKey);

    std::cout << "Successfully created key: " << keyName << std::endl;
    return true;
}

/**
 * @brief Retrieves a key's data from the vault (including private key material).
 */
KeyData KeyVault::getKey(const std::string& keyName) const {

    std::cout << "Getting Key :" << keyName << std::endl;

    if (keyName == "MASTER") {
        KeyData mk;
        mk.keyName = "MASTER";
        mk.algorithm = "AES";
        mk.publicKey = getMasterKey();

        return mk;
    }

    fs::path keyPath = fs::path(storagePath) / keyName;

    if (!fs::exists(keyPath) || !fs::is_directory(keyPath)) {
        std::cerr << "Error: Key '" << keyName << "' not found." << std::endl;
        return KeyData{}; // Return an empty struct
    }

    return loadKeyFromFile(keyPath.string());
}

/**
 * @brief Gets the public-facing key material.
 * For AES, this is the symmetric key itself.
 * For RSA/EC, this is the public key.
 * @param keyName The name of the key.
 * @return The key as a string, or an empty string if not found.
 */
std::string KeyVault::getPublicKey(const std::string& keyName) const {
    // This function re-uses getKey, which loads the full key data.
    KeyData keyData = getKey(keyName);

    if (keyData.algorithm.empty()) {
        return ""; // getKey() already printed an error
    }

    return keyData.publicKey;

    // Should not happen if algorithm is known, but good to have.
    std::cerr << "Error: Unknown algorithm type in getPublicKey for " << keyName << std::endl;
    return "";
}

/**
 * @brief Gets only the metadata for a key (name, algo, parent) from metadata.txt.
 * This is more efficient than getKey() as it does not read the key files.
 * @param keyName The name of the key.
 * @return A KeyData struct with privateKey and publicKey fields guaranteed to be empty.
 */
KeyData KeyVault::getKeyMetadata(const std::string& keyName) const {
    KeyData keyData; // Will be returned (private/public keys empty)
    fs::path keyPath = fs::path(storagePath) / keyName;
    std::string metadataPath = keyPath / "metadata.txt";

    if (!fs::exists(metadataPath)) {
        std::cerr << "Error: Key metadata for '" << keyName << "' not found." << std::endl;
        return keyData; // Return empty struct
    }

    // 1. Read metadata
    std::ifstream metaFile(metadataPath);
    if (!metaFile) {
        std::cerr << "Error: Could not open metadata file at " << metadataPath << std::endl;
        return keyData; // Return empty struct
    }

    std::string line;
    std::getline(metaFile, line);
    std::stringstream ss(line);
    
    // Parse the "name,algo,parentKey" format
    std::getline(ss, keyData.keyName, ',');
    std::getline(ss, keyData.algorithm, ',');
    std::getline(ss, keyData.parentKey, ','); 
    
    metaFile.close();

    // privateKey and publicKey fields remain empty, as requested.
    return keyData;
}


/**
 * @brief Prints the details of a specific key to the console.
 */
void KeyVault::printKey(const std::string& keyName) {
    KeyData keyData = getKey(keyName);

    // getKey() will print an error if not found, but we check
    // the algorithm string to see if the returned struct is empty.
    if (keyData.algorithm.empty()) {
        return; // Key not found or was invalid
    }

    std::cout << "\n--- Key Details: " << keyData.keyName << " ---" << std::endl;
    std::cout << "  Algorithm: " << keyData.algorithm << std::endl;
    
    // Print parent key if it exists
    if (!keyData.parentKey.empty()) {
        std::cout << "  Parent Key: " << keyData.parentKey << std::endl;
    }

    if (keyData.algorithm == "AES") {
        std::cout << "  Symmetric Key (hex): " << keyData.publicKey << std::endl;
    } else {
        std::cout << "  Private Key: " << "\n" << keyData.privateKey << std::endl;
        std::cout << "  Public Key:  " << "\n" << keyData.publicKey << std::endl;
    }
    std::cout << "---------------------------------" << std::endl;
}

/**
 * @brief Securely deletes all keys and folders within the vault.
 */
void KeyVault::zeroizeAllKeys() {
    std::cout << "\nZeroizing all keys in " << storagePath << "..." << std::endl;
    try {
        if (fs::exists(storagePath)) {
            // Recursively remove the entire directory and all its contents
            fs::remove_all(storagePath);
            std::cout << "Vault contents deleted." << std::endl;
        }
        // Re-create the empty root directory
        fs::create_directory(storagePath);
        std::cout << "Vault directory recreated." << std::endl;
        
        // After zeroizing, we must create a new master key
        initializeMasterKey();

    } catch (const fs::filesystem_error& e) {
        std::cerr << "Error during zeroize: " << e.what() << std::endl;
    }
}

