#ifndef BASE_CRYPTO_PROCESSOR_H
#define BASE_CRYPTO_PROCESSOR_H

#include "KeyVault.h"
#include <string>
#include <map>

/**
 * @class BaseCryptoProcessor
 * @brief Handles wrapping (encrypting) and unwrapping (decrypting) keys
 * from a KeyVault using a parent key. Implements envelope encryption.
 */
class BaseCryptoProcessor {
public:
    /**
     * @brief Constructs the processor, linking it to a KeyVault.
     * It will load the wrapping log from the vault's storage path.
     * @param vault A reference to an existing KeyVault object.
     */
    BaseCryptoProcessor(KeyVault& vault);

    /**
     * @brief Wraps a child key using a parent key and a specified algorithm.
     * This encrypts the child's private key material and overwrites it
     * in the vault with the resulting ciphertext.
     *
     * @param parentKeyName The name of the key to use for wrapping (e.g., "RootAES").
     * @param childKeyName The name of the key to be wrapped (e.g., "MySecretKey").
     * @param algorithm The wrapping algorithm to use:
     * - "AES-KWP": AES Key Wrap with Padding (RFC 5649). Parent must be AES.
     * - "RSA-OAEP": RSAES-OAEP. Parent must be RSA.
     * - "ECDH+AES-KWP": ECIES-like scheme. Parent must be EC.
     * @return true if wrapping was successful, false otherwise.
     */
    bool wrapKey(const std::string& parentKeyName, const std::string& childKeyName, const std::string& algorithm);

    /**
     * @brief Unwraps a child key using its parent key.
     * This reads the child's encrypted private key, decrypts it using the
     * parent key, and returns the original plaintext private key.
     *
     * @param parentKeyName The name of the parent key that was used to wrap.
     * @param childKeyName The name of the key to unwrap.
     * @return The decrypted private key (hex-encoded) as a string.
     * Returns an empty string on failure.
     */
    bool unwrapKey(const std::string& parentKeyName, const std::string& childKeyName);

    KeyVault& vault; // Reference to the key vault
    std::map<std::string, std::string> wrapLog; // Maps childKeyName -> wrapAlgorithm
    std::string logFilePath; // Path to the wrap_log.txt

    /**
     * @brief Loads the wrap log file (e.g., "wrap_log.txt") from disk.
     */
    void loadWrapLog();

    /**
     * @brief Saves the current wrapLog map to disk.
     */
    void saveWrapLog();
};

#endif // BASE_CRYPTO_PROCESSOR_H
