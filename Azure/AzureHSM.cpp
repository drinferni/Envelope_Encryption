#include "AzureHSM.h"
#include <fstream>
#include <sstream>
#include <iostream>
#include <iomanip> // For hex formatting
#include <algorithm> // For std::find
#include <stdexcept> // For std::runtime_error

// --- OpenSSL Includes (minimal) ---
#include <openssl/rand.h> // For generateTempName
#include <openssl/err.h>  // For error reporting
// --- End OpenSSL Includes ---

// --- Internal Helper Functions ---

/**
 * @brief Encodes a raw byte buffer into a hex string.
 */
static std::string internal_hexEncode(const unsigned char* bytes, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << std::setw(2) << static_cast<int>(bytes[i]);
    }
    return ss.str();
}

/**
 * @brief Decodes a hex string into a raw byte buffer (std::vector).
 */
static std::vector<unsigned char> internal_hexDecode(const std::string& hexStr) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hexStr.length(); i += 2) {
        std::string byteString = hexStr.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

/**
 * @brief Helper to generate a simple UUID-like string for temp keys
 */
static std::string generateTempName() {
    unsigned char uuid[16];
    if (RAND_bytes(uuid, sizeof(uuid)) != 1) {
        // Fallback in case RAND_bytes fails
        return "temp_dek_fallback_" + std::to_string(std::time(0));
    }
    return "temp_dek_" + internal_hexEncode(uuid, sizeof(uuid));
}

// --- Removed manual crypto helpers (readPEMKey, deriveECDHKey) ---
// --- They belong in BaseCryptoProcessor.cpp ---

// --- End Internal Helper Functions ---


/**
 * @brief Constructor
 * Initializes file paths and loads the policy maps from disk.
 */
AzureHSM::AzureHSM(KeyVault& vault, const std::string& userDEKFile)
    : BaseCryptoProcessor(vault) // Call the parent constructor
{
    // Use the vault's storage path as the base for our policy files
    std::string basePath = vault.storagePath;
    this->userDEKFilePath = basePath + "/" + userDEKFile;

    loadUserDEKMap();
    std::cout << "AzureHSM initialized. Loaded " << userDEKMap.size() << " user policies  << " << std::endl;
}




bool AzureHSM::generateDEK(const std::string& username, const std::string& DEKName, const std::string& wrapAlgorithm) {
    std::cout << "Attempting to generate DEK '" << DEKName << "' for user '" << username << "'..." << std::endl;


    if (!vault.createKey(DEKName, "AES")) {
        std::cerr << "Error: Could not create key '" << DEKName << "'. It may already exist." << std::endl;
        return false;
    }

    bool wrapSuccess = BaseCryptoProcessor::wrapKey("MASTER", DEKName, "AES-KWP");

    if (!wrapSuccess) {
        std::cerr << "Error: Failed to wrap new DEK '" << DEKName << "' with master key." << std::endl;
        return false;
    }

    // 4. Get the wrapped key to update its parent metadata
    KeyData newDEK = vault.getKey(DEKName);
    if (newDEK.algorithm.empty()) {
        std::cerr << "Error: Failed to retrieve wrapped DEK '" << DEKName << "' after wrap." << std::endl;
        // Key is wrapped, but we can't update metadata. This is a recoverable state,
        // but we'll flag it. The key is secure, but parentage is unknown.
    }

    // 6. Grant the user access to this new DEK
    grantDEKAccess(username, DEKName);
    
    std::cout << "Successfully generated and wrapped DEK '" << DEKName 
              << "', granting access to '" << username << "'." << std::endl;
    return true;
}

// --- Public Helper Functions ---

bool AzureHSM::canUserAccessDEK(const std::string& username, const std::string& DEKName) const {
    auto userIt = userDEKMap.find(username);
    if (userIt == userDEKMap.end()) {
        return false; // User not found
    }
    
    // User found, check if DEKName is in their vector
    const auto& DEKs = userIt->second;
    return std::find(DEKs.begin(), DEKs.end(), DEKName) != DEKs.end();
}

bool AzureHSM::grantDEKAccess(const std::string& username, const std::string& DEKName) {
    // Check if user exists (from the file). If not, they will be added.
    if (userDEKMap.find(username) == userDEKMap.end()) {
        std::cout << "Grant: Adding new user '" << username << "' to policy." << std::endl;
    }
    
    // Get the user's list of DEKs (or create it)
    auto& DEKs = userDEKMap[username];
    
    // Add the DEK if it's not already there
    if (std::find(DEKs.begin(), DEKs.end(), DEKName) == DEKs.end()) {
        DEKs.push_back(DEKName);
        saveUserDEKMap(); // Persist the change
        std::cout << "Grant: Access for '" << username << "' to '" << DEKName << "' saved." << std::endl;
    } else {
        std::cout << "Grant: Access for '" << username << "' to '" << DEKName << "' already exists." << std::endl;
    }
    return true;
}



std::vector<std::string> AzureHSM::getDEKsForUser(const std::string& username) const {
    auto it = userDEKMap.find(username);
    if (it != userDEKMap.end()) {
        return it->second; // Return the vector of DEKs
    }
    return {}; // Return empty vector
}


// --- Private File I/O Helpers ---

// Generic helper to load a map<string, vector<string>> from a CSV file
void loadMapFromFile(const std::string& filePath, std::map<std::string, std::vector<std::string>>& map) {
    std::ifstream file(filePath);
    if (!file) {
        std::cout << "Policy file not found: " << filePath << ". A new file will be created on save." << std::endl;
        return;
    }
    
    map.clear();
    std::string line;
    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string segment;
        std::string key; // This will be username or DEKName
        
        if (std::getline(ss, key, ',')) {
            if (key.empty()) continue;
            map[key] = std::vector<std::string>(); // Ensure key exists
            
            while (std::getline(ss, segment, ',')) {
                if (!segment.empty()) {
                    map[key].push_back(segment);
                }
            }
        }
    }
    file.close();
}

// Generic helper to save a map<string, vector<string>> to a CSV file
void saveMapToFile(const std::string& filePath, const std::map<std::string, std::vector<std::string>>& map) {
    std::ofstream file(filePath);
    if (!file) {
        std::cerr << "Error: Could not write to policy file: " << filePath << std::endl;
        return;
    }
    
    for (const auto& pair : map) {
        file << pair.first;
        for (const auto& value : pair.second) {
            file << "," << value;
        }
        file << "\n";
    }
    file.close();
}

void AzureHSM::loadUserDEKMap() {
    loadMapFromFile(this->userDEKFilePath, this->userDEKMap);
}

void AzureHSM::saveUserDEKMap() {
    saveMapToFile(this->userDEKFilePath, this->userDEKMap);
}

