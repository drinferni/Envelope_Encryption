#ifndef KEY_VAULT_H
#define KEY_VAULT_H

#include "Utils.cpp"
#include <string>
#include <map>
#include <vector>

// This struct holds the key data in memory.
struct KeyData {
    std::string keyName;    // The name of the key (e.g., "MyPersonalAESKey")
    std::string algorithm;
    std::string privateKey; // For private keys or symmetric keys (like AES)
    std::string publicKey;  // For public keys (empty for AES)
    std::string parentKey;  // Name of the key used to wrap this key
};

/**
 * @class KeyVault
 * @brief Manages creation, storage, and retrieval of cryptographic keys
 * in a file-based vault.
 */
class KeyVault {
public:
    /**
     * @brief Constructs a KeyVault, creating the main storage directory if needed.
     * @param storagePath The path to the main "KeyLocker" directory.
     */
    KeyVault(const std::string& storagePath);

    /**
     * @brief Creates a new key, storing it in its own subdirectory.
     * @param keyName The unique name for the key (will be the folder name).
     * @param algorithm The algorithm ("AES", "RSA", "EC").
     * @param parentKeyName The name of the parent key used for wrapping (optional).
     * @return true if creation was successful, false otherwise (e.g., key exists).
     */
    bool createKey(const std::string& keyName, const std::string& algorithm, const std::string& parentKeyName = "");

    /**
     * @brief Retrieves a key's data from the vault (including private key material).
     * @param keyName The name of the key to retrieve.
     * @return A KeyData struct. If the key is not found, the struct will be empty
     * (e.g., algorithm string will be empty).
     */
    KeyData getKey(const std::string& keyName) const;

    /**
     * @brief Gets the public-facing key material.
     * For AES, this is the symmetric key itself.
     * For RSA/EC, this is the public key.
     * @param keyName The name of the key.
     * @return The key as a string, or an empty string if not found.
     */
    std::string getPublicKey(const std::string& keyName) const;

    /**
     * @brief Gets only the metadata for a key (name, algo, parent) from metadata.txt.
     * This is more efficient than getKey() as it does not read the key files.
     * @param keyName The name of the key.
     * @return A KeyData struct with privateKey and publicKey fields guaranteed to be empty.
     */
    KeyData getKeyMetadata(const std::string& keyName) const;

    /**
     * @brief Prints the details of a specific key to the console.
     * @param keyName The name of the key to print.
     */
    void printKey(const std::string& keyName);

    /**
     * @brief Securely deletes all keys and folders within the vault.
     * This recursively removes the entire storagePath directory
     * and then recreates the empty root vault directory.
     * A new master key is generated after this operation.
     */
    void zeroizeAllKeys();

    /**
     * @brief Returns the master AES key.
     * The key is loaded/created during KeyVault initialization.
     * @return The master key as a hex-encoded string.
     */
    std::string getMasterKey() const;

    std::string storagePath; // The root directory, e.g., "KeyLocker"
    std::string masterKey;   // The loaded/created master AES key

    /**
     * @brief Helper function to read a file's entire content into a string.
     * @param path The full path to the file.
     * @return The file's content as a string.
     */
    std::string readFileContent(const std::string& path) const;

    /**
     * @brief Loads key data from a specific key directory.
     * @param path The path to the key's folder (e.g., "KeyLocker/MyAESKey").
     * @return A populated KeyData struct.
     */
    KeyData loadKeyFromFile(const std::string& path) const;

    /**
     * @brief Saves key data to a specific key directory.
     * @param path The path to the key's folder (e.g., "KeyLocker/MyAESKey").
     * @param keyData The KeyData struct to save.
     */
    void saveKeyToFile(const std::string& path, const KeyData& keyData);

    /**
     * @brief Loads the master key from master_key.key, or creates one
     * if it doesn't exist.
     */
    void initializeMasterKey();
};

#endif // KEY_VAULT_H

