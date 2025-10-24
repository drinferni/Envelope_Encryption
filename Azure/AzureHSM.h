#ifndef AzureHSM_H
#define AzureHSM_H

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
 * @class AzureHSM
 * @brief Simulates an HSM by adding a user authorization layer on top
 * of the BaseCryptoProcessor.
 *
 * It controls which users can use which "DEKs" (parent keys) to wrap
 * or unwrap "DEKs" (child keys).
 */
class AzureHSM : public BaseCryptoProcessor {
public:
    /**
     * @brief Constructs the HSM, linking it to a KeyVault and loading user policies.
     * @param vault A reference to the existing KeyVault.
     * @param userDEKFile The filename (relative to vault path) for the user-to-DEK policy file.
     * E.g., "user_DEK_permissions.txt"
     */
    AzureHSM(KeyVault& vault, const std::string& userDEKFile);

    /**
     * @brief Checks if a user has permission to use a specific DEK.
     * @param username The user to check.
     * @param DEKName The DEK to check.
     * @return true if user is in the map and DEKName is in their vector.
     */
    bool canUserAccessDEK(const std::string& username, const std::string& DEKName) const;
    
    /**
     * @brief Manually grants a user access to a DEK and saves the map.
     * Creates the user in the map if they don't exist.
     *
     * @param username The user.
     * @param DEKName The DEK.
     * @return true on success.
     */
    bool grantDEKAccess(const std::string& username, const std::string& DEKName);

    
    /**
     * @brief Gets all DEKs a user has been granted access to.
     * @param username The name of the user.
     * @return A vector of DEK names.
     */
    std::vector<std::string> getDEKsForUser(const std::string& username) const;

    /**
     * @brief Generates a new DEK (AES key), wraps it with the vault's master key,
     * and grants the user access.
     *
     * @param username The user to grant access to this new DEK.
     * @param DEKName The name for the new DEK.
     * @param wrapAlgorithm The algorithm to use for wrapping (AES-KW or AES-KWP).
     * @return true if successful.
     */
    bool generateDEK(const std::string& username, const std::string& DEKName, const std::string& wrapAlgorithm);


private:
    /**
     * @brief Loads the user-to-DEK policy map from its file.
     * Assumes format: username,DEK1,DEK2,...
     */
    void loadUserDEKMap();
    
    /**
     * @brief Saves the current user-to-DEK policy map to its file.
     */
    void saveUserDEKMap();
    

    // Map 1: User -> list of DEKs they can use
    std::map<std::string, std::vector<std::string>> userDEKMap;
    std::string userDEKFilePath;
};

#endif // AzureHSM_H

