#ifndef AWSHSM_H
#define AWSHSM_H

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
 * @class AWSHSM
 * @brief Simulates an HSM by adding a user authorization layer on top
 * of the BaseCryptoProcessor.
 *
 * It controls which users can use which "CMKs" (parent keys) to wrap
 * or unwrap "DEKs" (child keys).
 */
class AWSHSM : public BaseCryptoProcessor {
public:
    /**
     * @brief Constructs the HSM, linking it to a KeyVault and loading user policies.
     * @param vault A reference to the existing KeyVault.
     * @param userCmkFile The filename (relative to vault path) for the user-to-CMK policy file.
     * E.g., "user_cmk_permissions.txt"
     */
    AWSHSM(KeyVault& vault, const std::string& userCmkFile);

    /**
     * @brief Wraps a key, but first checks if the user is authorized for the parent key (CMK).
     * If successful, it also logs the new child key (DEK) under the parent (CMK).
     *
     * @param username The user performing the operation.
     * @param parentKeyName The name of the CMK (Customer Master Key).
     * @param childKeyName The name of the DEK (Data Encryption Key) to be wrapped.
     * @param algorithm The wrapping algorithm to use (e.g., "AES-KWP").
     * @return true if authorization and wrapping succeed.
     */
    bool wrapKey(const std::string& username, const std::string& parentKeyName, const std::string& childKeyName, const std::string& algorithm);

    /**
     * @brief Unwraps a key, but first checks if the user is authorized for the parent key (CMK).
     *
     * @param username The user performing the operation.
     * @param parentKeyName The name of the CMK (Customer Master Key).
     * @param childKeyName The name of the DEK (Data Encryption Key) to unwrap.
     * @return The decrypted private key (hex-encoded) as a string. Empty on failure.
     */
    std::string unwrapKey(const std::string& username, const std::string& parentKeyName, const std::string& childKeyName);

    /**
     * @brief Checks if a user has permission to use a specific CMK.
     * @param username The user to check.
     * @param cmkName The CMK to check.
     * @return true if user is in the map and cmkName is in their vector.
     */
    bool canUserAccessCmk(const std::string& username, const std::string& cmkName) const;
    
    /**
     * @brief Manually grants a user access to a CMK and saves the map.
     * Creates the user in the map if they don't exist.
     *
     * @param username The user.
     * @param cmkName The CMK.
     * @return true on success.
     */
    bool grantCmkAccess(const std::string& username, const std::string& cmkName);

    /**
     * @brief Gets all DEKs that are known to be wrapped by a specific CMK.
     * @param cmkName The name of the parent CMK.
     * @return A vector of DEK names.
     */
    std::vector<std::string> getDeksForCmk(const std::string& cmkName) const;
    
    /**
     * @brief Gets all CMKs a user has been granted access to.
     * @param username The name of the user.
     * @return A vector of CMK names.
     */
    std::vector<std::string> getCmksForUser(const std::string& username) const;

    /**
     * @brief Generates a new CMK (AES key), wraps it with the vault's master key,
     * and grants the user access.
     *
     * @param username The user to grant access to this new CMK.
     * @param cmkName The name for the new CMK.
     * @param wrapAlgorithm The algorithm to use for wrapping (AES-KW or AES-KWP).
     * @return true if successful.
     */
    bool generateCMK(const std::string& username, const std::string& cmkName, const std::string& wrapAlgorithm);

    /**
     * @brief Generates a new Data Key (DEK) wrapped by a CMK.
     * Returns both the plaintext and ciphertext of the DEK.
     *
     * @param username The user performing the operation (must be authorized for the CMK).
     * @param cmkName The parent CMK to use for wrapping.
     * @param wrapAlgorithm The wrapping algorithm (e.g., "AES-KWP").
     * @param dekAlgorithm The type of DEK to generate: "AES", "RSA", or "EC". Defaults to "AES".
     * @return A DataKey struct. Check with .isValid()
     */
    DataKey generateDataKey(const std::string& username, const std::string& cmkName, const std::string& wrapAlgorithm, const std::string& dekAlgorithm = "AES");

    /**
     * @brief Generates a new Data Key (DEK) wrapped by a CMK.
     * Returns only the ciphertext of the DEK, for cases where the
     * plaintext should not be exposed.
     *
     * @param username The user performing the operation (must be authorized for the CMK).
     * @param cmkName The parent CMK to use for wrapping.
     * @param wrapAlgorithm The wrapping algorithm (e.g., "AES-KWP").
     * @param dekAlgorithm The type of DEK to generate: "AES", "RSA", or "EC". Defaults to "AES".
     * @return The hex-encoded ciphertext of the new DEK. Empty on failure.
     */
    std::string generateDataKeyWithoutPlaintext(const std::string& username, const std::string& cmkName, const std::string& wrapAlgorithm, const std::string& dekAlgorithm = "AES");


private:
    /**
     * @brief Loads the user-to-CMK policy map from its file.
     * Assumes format: username,cmk1,cmk2,...
     */
    void loadUserCmkMap();
    
    /**
     * @brief Saves the current user-to-CMK policy map to its file.
     */
    void saveUserCmkMap();
    
    /**
     * @brief Loads the CMK-to-DEK log from its file.
     * Assumes format: cmkName,dek1,dek2,...
     */
    void loadCmkDekMap();
    
    /**
     * @brief Saves the current CMK-to-DEK log to its file.
     */
    void saveCmkDekMap();

    /**
     * @brief Internal helper to generate and wrap a new data key.
     * This contains the core crypto logic.
     *
     * @param cmkName The parent CMK to use for wrapping.
     * @param wrapAlgorithm The wrapping algorithm.
     * @param dekAlgorithm The type of DEK to generate ("AES", "RSA", "EC").
     * @return A DataKey struct.
     */
    DataKey internalGenerateAndWrap(const std::string& cmkName, const std::string& wrapAlgorithm, const std::string& dekAlgorithm);

    // Map 1: User -> list of CMKs they can use
    std::map<std::string, std::vector<std::string>> userCmkMap;
    // Map 2: CMK -> list of DEKs it has encrypted
    std::map<std::string, std::vector<std::string>> cmkDekMap;

    std::string userCmkFilePath;
    std::string cmkDekFilePath;
};

#endif // AWSHSM_H

