#include "GCHSM.h"
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
 * @brief Constructor
 * Initializes file paths and loads the policy maps from disk.
 */
GCHSM::GCHSM(KeyVault& vault, const std::string& userCryptoKeyFile)
    : BaseCryptoProcessor(vault) // Call the parent constructor
{
    // Use the vault's storage path as the base for our policy files
    std::string basePath = vault.storagePath;
    this->userCryptoKeyFilePath = basePath + "/" + userCryptoKeyFile;
    
    // We'll use a fixed name for the CryptoKey-DEK log
    this->CryptoKeyAlgoFilePath = basePath + "/CryptoKey_Algo_map.txt";

    loadUserCryptoKeyMap();
    loadCryptoKeyAlgoMap();
    std::cout << "GCHSM initialized. Loaded " << userCryptoKeyMap.size() << " user policies and "
              << CryptoKeyAlgoMap.size() << " CryptoKey-Algo mappings." << std::endl;
}



std::string GCHSM::encrypt(const std::string& username, const std::string& parentKeyName, const std::string& childkey) {

    if (!canUserAccessCryptoKey(username, parentKeyName)) {
        std::cerr << "AuthZ Error: User '" << username << "' is not authorized for CMK '" << parentKeyName << "'." << std::endl;
        return "";
    }
    
    std::cout << "AuthZ Success: User '" << username << "' authorized for CMK '" << parentKeyName << "'." << std::endl;

    return BaseCryptoProcessor::encrypt(parentKeyName,childkey,CryptoKeyAlgoMap[parentKeyName]);
}

std::string GCHSM::decrypt(const std::string& username, const std::string& parentKeyName, const std::string& childKey) {

    if (!canUserAccessCryptoKey(username, parentKeyName)) {
        std::cerr << "AuthZ Error: User '" << username << "' is not authorized for CMK '" << parentKeyName << "'." << std::endl;
        return "";
    }
    
    std::cout << "AuthZ Success: User '" << username << "' authorized for CMK '" << parentKeyName << "'." << std::endl;
    std::cout << "To decrypt " << childKey << std::endl;

    return BaseCryptoProcessor::decrypt(parentKeyName,childKey,CryptoKeyAlgoMap[parentKeyName]);
}



bool GCHSM::generateCryptoKey(const std::string& username, const std::string& CryptoKeyName, const std::string& wrapAlgorithm, std::string& wrapingAlgo) {
    std::cout << "Attempting to generate CryptoKey '" << CryptoKeyName << "' for user '" << username << "'..." << std::endl;

    // 1. Validate algorithm
    if (wrapAlgorithm != "AES-KWP" && wrapAlgorithm != "AES-KW") {
        std::cerr << "Error: Invalid wrap algorithm. Must be 'AES-KWP' or 'AES-KW'." << std::endl;
        return false;
    }


    std::string KeyAlgo = "AES";
    if (wrapAlgorithm == "RSA-OAEP") KeyAlgo = "RSA";


    // 2. Create the key in the vault (plaintext)
    if (!vault.createKey(CryptoKeyName, KeyAlgo)) {
        std::cerr << "Error: Could not create key '" << CryptoKeyName << "'. It may already exist." << std::endl;
        return false;
    }

    // 3. Call BaseCryptoProcessor::wrapKey to wrap the new CryptoKey with the master key.
    // We pass "MASTER" as the parent key, which the vault will handle.
    bool wrapSuccess = BaseCryptoProcessor::wrapKey("MASTER", CryptoKeyName, wrapAlgorithm);

    if (!wrapSuccess) {
        std::cerr << "Error: Failed to wrap new CryptoKey '" << CryptoKeyName << "' with master key." << std::endl;
        return false;
    }

    // 4. Get the wrapped key to update its parent metadata
    KeyData newCryptoKey = vault.getKey(CryptoKeyName);
    if (newCryptoKey.algorithm.empty()) {
        std::cerr << "Error: Failed to retrieve wrapped CryptoKey '" << CryptoKeyName << "' after wrap." << std::endl;
        // Key is wrapped, but we can't update metadata. This is a recoverable state,
        // but we'll flag it. The key is secure, but parentage is unknown.
    }

    // 6. Grant the user access to this new CryptoKey
    grantCryptoKeyAccess(username, CryptoKeyName);

    CryptoKeyAlgoMap[CryptoKeyName] = wrapAlgorithm;

    saveCryptoKeyAlgoMap();
    saveUserCryptoKeyMap();
    
    std::cout << "Successfully generated and wrapped CryptoKey '" << CryptoKeyName 
              << "', granting access to '" << username << "'." << std::endl;
    return true;
}

// --- Public Helper Functions ---

bool GCHSM::canUserAccessCryptoKey(const std::string& username, const std::string& CryptoKeyName) const {
    auto userIt = userCryptoKeyMap.find(username);
    if (userIt == userCryptoKeyMap.end()) {
        return false; // User not found
    }
    
    // User found, check if CryptoKeyName is in their vector
    const auto& CryptoKeys = userIt->second;
    return std::find(CryptoKeys.begin(), CryptoKeys.end(), CryptoKeyName) != CryptoKeys.end();
}

bool GCHSM::grantCryptoKeyAccess(const std::string& username, const std::string& CryptoKeyName) {
    // Check if user exists (from the file). If not, they will be added.
    if (userCryptoKeyMap.find(username) == userCryptoKeyMap.end()) {
        std::cout << "Grant: Adding new user '" << username << "' to policy." << std::endl;
    }
    
    // Get the user's list of CryptoKeys (or create it)
    auto& CryptoKeys = userCryptoKeyMap[username];
    
    // Add the CryptoKey if it's not already there
    if (std::find(CryptoKeys.begin(), CryptoKeys.end(), CryptoKeyName) == CryptoKeys.end()) {
        CryptoKeys.push_back(CryptoKeyName);
        saveUserCryptoKeyMap(); // Persist the change
        std::cout << "Grant: Access for '" << username << "' to '" << CryptoKeyName << "' saved." << std::endl;
    } else {
        std::cout << "Grant: Access for '" << username << "' to '" << CryptoKeyName << "' already exists." << std::endl;
    }
    return true;
}


std::vector<std::string> GCHSM::getCryptoKeysForUser(const std::string& username) const {
    auto it = userCryptoKeyMap.find(username);
    if (it != userCryptoKeyMap.end()) {
        return it->second; // Return the vector of CMKs
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
        std::string key; // This will be username or CryptoKeyName
        
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




// Load map<string, string> from a file where each line is "key,value"
void GCHSM::loadMapString(const std::string& filePath, std::map<std::string, std::string>& map) {
    std::ifstream file(filePath);
    if (!file) return; // File not found

    map.clear();
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;

        std::stringstream ss(line);
        std::string key, value;

        if (std::getline(ss, key, ',') && std::getline(ss, value)) {
            map[key] = value; // store single string
        }
    }
}

// Save map<string, string> to file
void GCHSM::saveMapString(const std::string& filePath, const std::map<std::string, std::string>& map) {
    std::ofstream file(filePath);
    if (!file) return;

    for (const auto& pair : map)
        file << pair.first << "," << pair.second << "\n";
}




void GCHSM::loadUserCryptoKeyMap() {
    loadMapFromFile(this->userCryptoKeyFilePath, this->userCryptoKeyMap);
}

void GCHSM::saveUserCryptoKeyMap() {
    saveMapToFile(this->userCryptoKeyFilePath, this->userCryptoKeyMap);
}

void GCHSM::loadCryptoKeyAlgoMap() {
    loadMapString(this->CryptoKeyAlgoFilePath, this->CryptoKeyAlgoMap);
}

void GCHSM::saveCryptoKeyAlgoMap() {
    saveMapString(this->CryptoKeyAlgoFilePath, this->CryptoKeyAlgoMap);
}

