#include "AWSHSM.h"
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
AWSHSM::AWSHSM(KeyVault& vault, const std::string& userCmkFile)
    : BaseCryptoProcessor(vault) // Call the parent constructor
{
    // Use the vault's storage path as the base for our policy files
    std::string basePath = vault.storagePath;
    this->userCmkFilePath = basePath + "/" + userCmkFile;
    
    // We'll use a fixed name for the CMK-DEK log
    this->cmkDekFilePath = basePath + "/cmk_dek_map.txt";

    loadUserCmkMap();
    loadCmkDekMap();
    std::cout << "AWSHSM initialized. Loaded " << userCmkMap.size() << " user policies and "
              << cmkDekMap.size() << " CMK-DEK mappings." << std::endl;
}

// --- Public Authorization-Wrapped Functions ---

bool AWSHSM::wrapKey(const std::string& username, const std::string& parentKeyName, const std::string& childKeyName, const std::string& algorithm) {
    // 1. Authorization Check
    if (!canUserAccessCmk(username, parentKeyName)) {
        std::cerr << "AuthZ Error: User '" << username << "' is not authorized for CMK '" << parentKeyName << "'." << std::endl;
        return false;
    }
    
    std::cout << "AuthZ Success: User '" << username << "' authorized for CMK '" << parentKeyName << "'." << std::endl;

    // 2. Call the parent's (BaseCryptoProcessor) wrapKey function
    bool wrapSuccess = BaseCryptoProcessor::wrapKey(parentKeyName, childKeyName, algorithm);
    
    // 3. If successful, update our DEK map and save
    if (wrapSuccess) {
        // Add to map, avoiding duplicates
        auto& deks = cmkDekMap[parentKeyName];
        if (std::find(deks.begin(), deks.end(), childKeyName) == deks.end()) {
             deks.push_back(childKeyName);
             // Save map to disk
             saveCmkDekMap();
        }
    }
    
    return wrapSuccess;
}

std::string AWSHSM::unwrapKey(const std::string& username, const std::string& parentKeyName, const std::string& childKeyName) {
    // 1. Authorization Check
    if (!canUserAccessCmk(username, parentKeyName)) {
        std::cerr << "AuthZ Error: User '" << username << "' is not authorized for CMK '" << parentKeyName << "'." << std::endl;
        return "";
    }
    
    std::cout << "AuthZ Success: User '" << username << "' authorized for CMK '" << parentKeyName << "'." << std::endl;

    // 2. Call the parent's (BaseCryptoProcessor) unwrapKey function
    BaseCryptoProcessor::unwrapKey(parentKeyName, childKeyName);

    std::string decryptedKey = vault.getPublicKey(childKeyName);

    BaseCryptoProcessor::wrapKey(parentKeyName,childKeyName,wrapLog[childKeyName]);

    return decryptedKey;

}

// --- NEW FUNCTION IMPLEMENTATIONS ---

/**
 * @brief Core logic for generating and wrapping a new data key.
 * This function now delegates generation to KeyVault and wrapping to BaseCryptoProcessor.
 */
DataKey AWSHSM::internalGenerateAndWrap(const std::string& cmkName, const std::string& wrapAlgorithm, const std::string& dekAlgorithm) {
    // 1. Generate a temporary name for the new DEK
    std::string dekName = generateTempName();

    // 2. Generate the DEK (plaintext) via KeyVault
    if (!vault.createKey(dekName, dekAlgorithm)) {
        std::cerr << "internalGenerateAndWrap: Failed to create temp DEK '" << dekName << "' of type '" << dekAlgorithm << "'." << std::endl;
        return {"", ""};
    }

    // 3. Get the plaintext DEK before it gets wrapped (to return to the user)
    KeyData dek_plaintext_data = vault.getKey(dekName);
    if (dek_plaintext_data.algorithm.empty()) {
        std::cerr << "internalGenerateAndWrap: Failed to retrieve temp DEK '" << dekName << "'." << std::endl;
        return {"", ""};
    }
    
    // Get the raw plaintext (private key for AES/EC/RSA)
    std::string dekPlaintext_raw = dek_plaintext_data.publicKey;

    if (!BaseCryptoProcessor::unwrapKey("MASTER", cmkName)) {
        std::cerr << "internalGenerateAndWrap: BaseCryptoProcessor::wrapKey failed." << std::endl;
        ERR_print_errors_fp(stderr);
        return {"", ""};
    }


    // 4. ***REVERTED LOGIC***:
    // Call BaseCryptoProcessor::wrapKey. This function will automatically:
    // 1. Load the CMK (cmkName).
    // 2. See it's wrapped by "MASTER".
    // 3. Call its *own* unwrapKey("MASTER", cmkName) to get the CMK plaintext.
    // 4. Use the CMK plaintext to wrap the DEK (dekName).
    // 5. Save the new ciphertext back into the dekName's key file.
    if (!BaseCryptoProcessor::wrapKey(cmkName, dekName, wrapAlgorithm)) {
        std::cerr << "internalGenerateAndWrap: BaseCryptoProcessor::wrapKey failed." << std::endl;
        ERR_print_errors_fp(stderr);
        return {"", ""};
    }

    if (!BaseCryptoProcessor::wrapKey("MASTER", cmkName, wrapLog[cmkName])) {
        std::cerr << "internalGenerateAndWrap: BaseCryptoProcessor::wrapKey failed." << std::endl;
        ERR_print_errors_fp(stderr);
    }

    // 5. Get the new wrapped key (ciphertext) from the file
    KeyData dek_wrapped_data = vault.getKey(dekName);
    if (dek_wrapped_data.algorithm.empty()) {
        std::cerr << "internalGenerateAndWrap: Failed to retrieve wrapped DEK data from '" << dekName << "'." << std::endl;
        return {"", ""};
    }
    std::string ciphertext_raw = dek_wrapped_data.publicKey;
    
    // 8. Return the plaintext and ciphertext, hex-encoded as per the DataKey struct
    std::string dekPlaintext_hex = internal_hexEncode((const unsigned char*)dekPlaintext_raw.data(), dekPlaintext_raw.length());
    std::string ciphertext_hex = internal_hexEncode((const unsigned char*)ciphertext_raw.data(), ciphertext_raw.length());

    std::cout << "DEK generated" << std::endl;

    return {dekPlaintext_hex, ciphertext_hex};
}


DataKey AWSHSM::generateDataKey(const std::string& username, const std::string& cmkName, const std::string& wrapAlgorithm, const std::string& dekAlgorithm) {
    // 1. Authorization Check
    if (!canUserAccessCmk(username, cmkName)) {
        std::cerr << "AuthZ Error: User '" << username << "' is not authorized for CMK '" << cmkName << "'." << std::endl;
        return {"", ""};
    }

    std::cout << "AuthZ Success: User '" << username << "' authorized for CMK '" << cmkName << "'." << std::endl;

    // 2. Call internal generation and wrapping function
    // *** MODIFIED LINE: Pass all parameters ***
    return internalGenerateAndWrap(cmkName, wrapAlgorithm, dekAlgorithm);
}

std::string AWSHSM::generateDataKeyWithoutPlaintext(const std::string& username, const std::string& cmkName, const std::string& wrapAlgorithm, const std::string& dekAlgorithm) {
    // 1. Authorization Check
    if (!canUserAccessCmk(username, cmkName)) {
        std::cerr << "AuthZ Error: User '" << username << "' is not authorized for CMK '" << cmkName << "'." << std::endl;
        return "";
    }
    
    std::cout << "AuthZ Success: User '" << username << "' authorized for CMK '" << cmkName << "'." << std::endl;
    
    // 2. Call internal generation and wrapping function
    // *** MODIFIED LINE: Pass all parameters ***
    DataKey dk = internalGenerateAndWrap(cmkName, wrapAlgorithm, dekAlgorithm);

    // 3. Return only the ciphertext
    return dk.ciphertextHex;
}


bool AWSHSM::generateCMK(const std::string& username, const std::string& cmkName, const std::string& wrapAlgorithm) {
    std::cout << "Attempting to generate CMK '" << cmkName << "' for user '" << username << "'..." << std::endl;

    // 1. Validate algorithm
    if (wrapAlgorithm != "AES-KWP" && wrapAlgorithm != "AES-KW") {
        std::cerr << "Error: Invalid wrap algorithm. Must be 'AES-KWP' or 'AES-KW'." << std::endl;
        return false;
    }

    // 2. Create the key in the vault (plaintext)
    if (!vault.createKey(cmkName, "AES")) {
        std::cerr << "Error: Could not create key '" << cmkName << "'. It may already exist." << std::endl;
        return false;
    }

    // 3. Call BaseCryptoProcessor::wrapKey to wrap the new CMK with the master key.
    // We pass "MASTER" as the parent key, which the vault will handle.
    bool wrapSuccess = BaseCryptoProcessor::wrapKey("MASTER", cmkName, wrapAlgorithm);

    if (!wrapSuccess) {
        std::cerr << "Error: Failed to wrap new CMK '" << cmkName << "' with master key." << std::endl;
        return false;
    }

    // 4. Get the wrapped key to update its parent metadata
    KeyData newCMK = vault.getKey(cmkName);
    if (newCMK.algorithm.empty()) {
        std::cerr << "Error: Failed to retrieve wrapped CMK '" << cmkName << "' after wrap." << std::endl;
        // Key is wrapped, but we can't update metadata. This is a recoverable state,
        // but we'll flag it. The key is secure, but parentage is unknown.
    }

    // 6. Grant the user access to this new CMK
    grantCmkAccess(username, cmkName);
    
    std::cout << "Successfully generated and wrapped CMK '" << cmkName 
              << "', granting access to '" << username << "'." << std::endl;
    return true;
}

// --- Public Helper Functions ---

bool AWSHSM::canUserAccessCmk(const std::string& username, const std::string& cmkName) const {
    auto userIt = userCmkMap.find(username);
    if (userIt == userCmkMap.end()) {
        return false; // User not found
    }
    
    // User found, check if cmkName is in their vector
    const auto& cmks = userIt->second;
    return std::find(cmks.begin(), cmks.end(), cmkName) != cmks.end();
}

bool AWSHSM::grantCmkAccess(const std::string& username, const std::string& cmkName) {
    // Check if user exists (from the file). If not, they will be added.
    if (userCmkMap.find(username) == userCmkMap.end()) {
        std::cout << "Grant: Adding new user '" << username << "' to policy." << std::endl;
    }
    
    // Get the user's list of CMKs (or create it)
    auto& cmks = userCmkMap[username];
    
    // Add the CMK if it's not already there
    if (std::find(cmks.begin(), cmks.end(), cmkName) == cmks.end()) {
        cmks.push_back(cmkName);
        saveUserCmkMap(); // Persist the change
        std::cout << "Grant: Access for '" << username << "' to '" << cmkName << "' saved." << std::endl;
    } else {
        std::cout << "Grant: Access for '" << username << "' to '" << cmkName << "' already exists." << std::endl;
    }
    return true;
}

std::vector<std::string> AWSHSM::getDeksForCmk(const std::string& cmkName) const {
    auto it = cmkDekMap.find(cmkName);
    if (it != cmkDekMap.end()) {
        return it->second; // Return the vector of DEKs
    }
    return {}; // Return empty vector
}

std::vector<std::string> AWSHSM::getCmksForUser(const std::string& username) const {
    auto it = userCmkMap.find(username);
    if (it != userCmkMap.end()) {
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
        std::string key; // This will be username or cmkName
        
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

void AWSHSM::loadUserCmkMap() {
    loadMapFromFile(this->userCmkFilePath, this->userCmkMap);
}

void AWSHSM::saveUserCmkMap() {
    saveMapToFile(this->userCmkFilePath, this->userCmkMap);
}

void AWSHSM::loadCmkDekMap() {
    loadMapFromFile(this->cmkDekFilePath, this->cmkDekMap);
}

void AWSHSM::saveCmkDekMap() {
    saveMapToFile(this->cmkDekFilePath, this->cmkDekMap);
}

