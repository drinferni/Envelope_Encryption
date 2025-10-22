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

// --- OpenSSL Helper Functions ---

/**
 * @brief Encodes a raw byte buffer into a hex string.
 */
std::string hexEncode(const unsigned char* bytes, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

/**
 * @brief Generates a 256-bit (32-byte) AES key and returns it as a hex string.
 */
std::string generateAESKey() {
    // 256 bits = 32 bytes
    unsigned char key[32];
    if (RAND_bytes(key, sizeof(key)) != 1) {
        std::cerr << "Error: OpenSSL RAND_bytes failed." << std::endl;
        return ""; // Error
    }
    return hexEncode(key, sizeof(key));
}

/**
 * @brief Serializes a private EVP_PKEY to a PEM string.
 */
std::string pkeyToString_private(EVP_PKEY *pkey) {
    // Use a Memory BIO (Basic I/O) to write the key to memory
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        std::cerr << "Error: OpenSSL BIO_new failed." << std::endl;
        return "";
    }

    // Write the private key to the BIO in PKCS8 (modern) format
    // No encryption on the PEM block itself (last NULLs)
    if (PEM_write_bio_PKCS8PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        std::cerr << "Error: OpenSSL PEM_write_bio_PKCS8PrivateKey failed." << std::endl;
        BIO_free(bio);
        return "";
    }

    char *data;
    long len = BIO_get_mem_data(bio, &data);
    std::string str(data, len);
    BIO_free(bio);
    return str;
}

/**
 * @brief Serializes a public EVP_PKEY to a PEM string.
 */
std::string pkeyToString_public(EVP_PKEY *pkey) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        std::cerr << "Error: OpenSSL BIO_new failed." << std::endl;
        return "";
    }

    // Write the public key to the BIO
    if (PEM_write_bio_PUBKEY(bio, pkey) != 1) {
        std::cerr << "Error: OpenSSL PEM_write_bio_PUBKEY failed." << std::endl;
        BIO_free(bio);
        return "";
    }

    char *data;
    long len = BIO_get_mem_data(bio, &data);
    std::string str(data, len);
    BIO_free(bio);
    return str;
}

// --- End OpenSSL Helper Functions ---


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
    // As requested: "metadata ( name and algo ) separated by comma"
    // Updated to use keyData.keyName
    metaFile << keyData.keyName << "," << keyData.algorithm;
    metaFile.close();

    // 2. Write key files based on algorithm
    if (keyData.algorithm == "AES") {
        std::ofstream keyFile(fs::path(path) / "key.txt");
        if (keyFile) {
            keyFile << keyData.privateKey;
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
    
    // Parse the "name,algo" format
    // Updated to use keyData.keyName
    std::getline(ss, keyData.keyName, ',');
    std::getline(ss, keyData.algorithm, ',');
    
    metaFile.close();

    // 2. Read key files based on algorithm
    if (keyData.algorithm == "AES") {
        keyData.privateKey = readFileContent(fs::path(path) / "key.txt");
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
        // If it already exists, it does nothing.
        fs::create_directory(this->storagePath);
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Error creating storage directory " << this->storagePath 
                  << ": " << e.what() << std::endl;
    }
}

/**
 * @brief Creates a new key, storing it in its own subdirectory.
 *
 * *** THIS FUNCTION IS MODIFIED TO USE OPENSSL ***
 */
bool KeyVault::createKey(const std::string& keyName, const std::string& algorithm) {
    fs::path keyPath = fs::path(storagePath) / keyName;

    // Check for duplicates as requested
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

    // --- Real Key Generation using OpenSSL ---
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    if (algorithm == "AES") {
        newKey.privateKey = generateAESKey();
        if (newKey.privateKey.empty()) {
            std::cerr << "Error: AES key generation failed for " << keyName << std::endl;
            fs::remove(keyPath); // Clean up empty folder
            return false;
        }
        // publicKey remains empty for symmetric key

    } else if (algorithm == "RSA") {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
        if (!ctx) {
            std::cerr << "Error: OpenSSL EVP_PKEY_CTX_new_id failed for RSA." << std::endl;
            fs::remove(keyPath); return false;
        }
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            std::cerr << "Error: OpenSSL EVP_PKEY_keygen_init failed for RSA." << std::endl;
            EVP_PKEY_CTX_free(ctx); fs::remove(keyPath); return false;
        }
        // Set RSA key bits to 2048
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
            std::cerr << "Error: OpenSSL EVP_PKEY_CTX_set_rsa_keygen_bits failed." << std::endl;
            EVP_PKEY_CTX_free(ctx); fs::remove(keyPath); return false;
        }
        
        // Generate the key
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            std::cerr << "Error: OpenSSL EVP_PKEY_keygen failed for RSA." << std::endl;
            EVP_PKEY_CTX_free(ctx); fs::remove(keyPath); return false;
        }

        EVP_PKEY_CTX_free(ctx);

    } else if (algorithm == "EC") {
        ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
         if (!ctx) {
            std::cerr << "Error: OpenSSL EVP_PKEY_CTX_new_id failed for EC." << std::endl;
            fs::remove(keyPath); return false;
        }
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            std::cerr << "Error: OpenSSL EVP_PKEY_keygen_init failed for EC." << std::endl;
            EVP_PKEY_CTX_free(ctx); fs::remove(keyPath); return false;
        }
        // Set EC curve to prime256v1 (NIST P-256)
        if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
            std::cerr << "Error: OpenSSL EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed." << std::endl;
            EVP_PKEY_CTX_free(ctx); fs::remove(keyPath); return false;
        }

        // Generate the key
        if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
            std::cerr << "Error: OpenSSL EVP_PKEY_keygen failed for EC." << std::endl;
            EVP_PKEY_CTX_free(ctx); fs::remove(keyPath); return false;
        }

        EVP_PKEY_CTX_free(ctx);

    } else {
        std::cerr << "Error: Unknown algorithm '" << algorithm << "'." << std::endl;
        fs::remove(keyPath);
        return false;
    }

    // For RSA and EC, serialize the generated pkey object to strings
    if (algorithm == "RSA" || algorithm == "EC") {
        newKey.privateKey = pkeyToString_private(pkey);
        newKey.publicKey = pkeyToString_public(pkey);
        EVP_PKEY_free(pkey); // Free the key object

        if (newKey.privateKey.empty() || newKey.publicKey.empty()) {
            std::cerr << "Error: Key string serialization failed for " << keyName << std::endl;
            fs::remove(keyPath);
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
 * @brief Retrieves a key's data from the vault.
 */
KeyData KeyVault::getKey(const std::string& keyName) const {
    fs::path keyPath = fs::path(storagePath) / keyName;

    if (!fs::exists(keyPath) || !fs::is_directory(keyPath)) {
        std::cerr << "Error: Key '" << keyName << "' not found." << std::endl;
        return KeyData{}; // Return an empty struct
    }

    return loadKeyFromFile(keyPath.string());
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

    // Updated to use keyData.keyName
    std::cout << "\n--- Key Details: " << keyData.keyName << " ---" << std::endl;
    std::cout << "  Algorithm: " << keyData.algorithm << std::endl;
    
    if (keyData.algorithm == "AES") {
        std::cout << "  Symmetric Key (hex): " << keyData.privateKey << std::endl;
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
        }
        // Re-create the empty root directory
        fs::create_directory(storagePath);
        std::cout << "Vault has been zeroized." << std::endl;
    } catch (const fs::filesystem_error& e) {
        std::cerr << "Error during zeroize: " << e.what() << std::endl;
    }
}

