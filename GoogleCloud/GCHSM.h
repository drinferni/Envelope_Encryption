#ifndef GCHSM_H
#define GCHSM_H

#include "../HSM/BaseCryptoProcessor.h"
#include "../HSM/KeyVault.h" // For KeyVault reference
#include <string>
#include <vector>
#include <map>

/**
 * @brief Structure to hold a Data Encryption Key,
 * in both plaintext and encrypted (wrapped) forms.
 */
struct DataKey {
    std::string plaintextHex;
    std::string ciphertextHex;
    
    /**
     * @brief Utility function to check if the DataKey is valid.
     * @return true if both fields are non-empty.
     */
    bool isValid() const {
        return !plaintextHex.empty() && !ciphertextHex.empty();
    }
};

/**
 * @class GCHSM
 * @brief Simulates an HSM by adding a user authorization layer on top
 * of the BaseCryptoProcessor.
 *
 * It controls which users can use which "CryptoKeys" (parent keys) to wrap
 * or unwrap "DEKs" (child keys).
 */
class GCHSM : public BaseCryptoProcessor {
public:
    /**
     * @brief Constructs the HSM, linking it to a KeyVault and loading user policies.
     * @param vault A reference to the existing KeyVault.
     * @param userCryptoKeyFile The filename (relative to vault path) for the user-to-CryptoKey policy file.
     * E.g., "user_CryptoKey_permissions.txt"
     */
    GCHSM(KeyVault& vault, const std::string& userCryptoKeyFile);

    bool generateCryptoKey(const std::string & username, const std::string & CryptoKeyName, const std::string & wrapAlgorithm, std::string &wrapingAlgo);

    /**
     * @brief Wraps a key, but first checks if the user is authorized for the parent key (CryptoKey).
     * If successful, it also logs the new child key (DEK) under the parent (CryptoKey).
     *
     * @param username The user performing the operation.
     * @param parentKeyName The name of the CryptoKey (Customer Master Key).
     * @param childKeyName The name of the DEK (Data Encryption Key) to be wrapped.
     * @param algorithm The wrapping algorithm to use (e.g., "AES-KWP").
     * @return true if authorization and wrapping succeed.
     */
    std::string encrypt(const std::string& username, const std::string& parentKeyName, const std::string& childkey);

    /**
     * @brief Unwraps a key, but first checks if the user is authorized for the parent key (CryptoKey).
     *
     * @param username The user performing the operation.
     * @param parentKeyName The name of the CryptoKey (Customer Master Key).
     * @param childKeyName The name of the DEK (Data Encryption Key) to unwrap.
     * @return The decrypted private key (hex-encoded) as a string. Empty on failure.
     */
    std::string decrypt(const std::string& username, const std::string& parentKeyName, const std::string& childKey);

    /**
     * @brief Checks if a user has permission to use a specific CryptoKey.
     * @param username The user to check.
     * @param CryptoKeyName The CryptoKey to check.
     * @return true if user is in the map and CryptoKeyName is in their vector.
     */
    bool canUserAccessCryptoKey(const std::string& username, const std::string& CryptoKeyName) const;
    
    /**
     * @brief Manually grants a user access to a CryptoKey and saves the map.
     * Creates the user in the map if they don't exist.
     *
     * @param username The user.
     * @param CryptoKeyName The CryptoKey.
     * @return true on success.
     */
    bool grantCryptoKeyAccess(const std::string& username, const std::string& CryptoKeyName);
    
    /**
     * @brief Gets all CryptoKeys a user has been granted access to.
     * @param username The name of the user.
     * @return A vector of CryptoKey names.
     */
    std::vector<std::string> getCryptoKeysForUser(const std::string& username) const;

private:
    void loadMapString(const std::string &filePath, std::map<std::string, std::string> &map);
    void saveMapString(const std::string &filePath, const std::map<std::string, std::string> &map);
    /**
     * @brief Loads the user-to-CryptoKey policy map from its file.
     * Assumes format: username,CryptoKey1,CryptoKey2,...
     */
    void loadUserCryptoKeyMap();
    
    /**
     * @brief Saves the current user-to-CryptoKey policy map to its file.
     */
    void saveUserCryptoKeyMap();
    
    /**
     * @brief Loads the CryptoKey-to-DEK log from its file.
     * Assumes format: CryptoKeyName,dek1,dek2,...
     */
    void loadCryptoKeyAlgoMap();
    
    /**
     * @brief Saves the current CryptoKey-to-DEK log to its file.
     */
    void saveCryptoKeyAlgoMap();

    // Map 1: User -> list of CryptoKeys they can use
    std::map<std::string, std::vector<std::string>> userCryptoKeyMap;
    // Map 2: CryptoKey -> list of DEKs it has encrypted
    std::map<std::string, std::string> CryptoKeyAlgoMap;

    std::string userCryptoKeyFilePath;
    std::string CryptoKeyAlgoFilePath;
};

#endif // GCHSM_H

