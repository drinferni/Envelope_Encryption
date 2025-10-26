#include "BaseCryptoProcessor.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <iomanip>
#include <stdexcept> // For std::runtime_error

// --- OpenSSL Includes ---
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/kdf.h>   // For HKDF (used in ECDH)
#include <openssl/rsa.h>   // For RSA_PKCS1_OAEP_PADDING
// --- End OpenSSL Includes ---


// --- Utility/Helper Functions ---
// These are duplicated from KeyVault.cpp or are new helpers
// needed for the crypto operations.

// --- End Utility/Helper Functions ---


BaseCryptoProcessor::BaseCryptoProcessor(KeyVault& v) : vault(v) {
    // Use the vault's path to store our log file
    this->logFilePath = vault.storagePath + "/wrap_log.txt";
    loadWrapLog();
}

void BaseCryptoProcessor::loadWrapLog() {

    std::cout << "Loading Wrap information" << std::endl;

    std::ifstream logFile(this->logFilePath);
    if (!logFile) {
        std::cout << "Wrap log not found. Will create a new one." << std::endl;
        return;
    }
    std::string line;
    while (std::getline(logFile, line)) {
        std::stringstream ss(line);
        std::string childKeyName, algorithm;
        if (std::getline(ss, childKeyName, ',') && std::getline(ss, algorithm)) {
            wrapLog[childKeyName] = algorithm;
        }
    }
    logFile.close();
}

void BaseCryptoProcessor::saveWrapLog() {
    std::ofstream logFile(this->logFilePath);
    if (!logFile) {
        std::cerr << "Error: Could not write to wrap log: " << this->logFilePath << std::endl;
        return;
    }
    for (const auto& pair : wrapLog) {
        logFile << pair.first << "," << pair.second << "\n";
    }
    logFile.close();
}


bool BaseCryptoProcessor::wrapKey(const std::string& parentKeyName, const std::string& childKeyName, const std::string& algorithm) {
    // 1. Get key data
    KeyData parentKey = vault.getKey(parentKeyName);
    KeyData childKey = vault.getKey(childKeyName);
    if (parentKey.keyName.empty() ) {
        std::cerr << "Error: Parent  not found." << std::endl;
        return false;
    }

    if (childKey.keyName.empty() ) {
        std::cerr << "Error: child  not found." << std::endl;
        return false;
    }


    // 2. Get the key material to wrap (child's private key)
    std::vector<unsigned char> keyToWrap_bytes = hexDecode(childKey.publicKey);
    std::vector<unsigned char> wrappedKey_bytes;
    std::string finalPayload; // This will be saved as the new "publicKey"

    try {
        if (algorithm == "AES-KWP") {
            if (parentKey.algorithm != "AES") {
                std::cerr << "Error: AES-KWP requires an AES parent key." << std::endl;
                return false;
            }
            std::vector<unsigned char> wrapKey_bytes = hexDecode(parentKey.publicKey);

            // AES-KWP uses AES-256-WRAP-PAD cipher
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
            
            // Allow wrapping
            EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
            
            if (EVP_EncryptInit_ex(ctx, EVP_aes_256_wrap_pad(), NULL, wrapKey_bytes.data(), NULL) != 1) {
                throw std::runtime_error("EVP_EncryptInit_ex failed");
            }
            
            // Resize buffer to be slightly larger
            wrappedKey_bytes.resize(keyToWrap_bytes.size() + 16); 
            int outlen = 0;
            
            if (EVP_EncryptUpdate(ctx, wrappedKey_bytes.data(), &outlen, keyToWrap_bytes.data(), keyToWrap_bytes.size()) != 1) {
                throw std::runtime_error("EVP_EncryptUpdate failed");
            }
            
            int finallen = 0;
            if (EVP_EncryptFinal_ex(ctx, wrappedKey_bytes.data() + outlen, &finallen) != 1) {
                throw std::runtime_error("EVP_EncryptFinal_ex failed");
            }

            wrappedKey_bytes.resize(outlen + finallen);
            finalPayload = hexEncode(wrappedKey_bytes.data(), wrappedKey_bytes.size());
            EVP_CIPHER_CTX_free(ctx);

        } else if (algorithm == "AES-KW") {
            if (parentKey.algorithm != "AES") {
                std::cerr << "Error: AES-KW requires an AES parent key." << std::endl;
                return false;
            }
            // RFC 3394 requires key data to be a multiple of 8 bytes
            if (keyToWrap_bytes.size() % 8 != 0) {
                std::cerr << "Error: AES-KW (RFC 3394) requires key data to be a multiple of 8 bytes." << std::endl;
                return false;
            }
            std::vector<unsigned char> wrapKey_bytes = hexDecode(parentKey.publicKey);

            // AES-KW uses AES-256-WRAP cipher (no padding)
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
            
            EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
            
            if (EVP_EncryptInit_ex(ctx, EVP_aes_256_wrap(), NULL, wrapKey_bytes.data(), NULL) != 1) {
                throw std::runtime_error("EVP_EncryptInit_ex failed");
            }
            
            // Output size for AES-KW is input size + 8 bytes (for the IV)
            wrappedKey_bytes.resize(keyToWrap_bytes.size() + 8); 
            int outlen = 0;
            
            if (EVP_EncryptUpdate(ctx, wrappedKey_bytes.data(), &outlen, keyToWrap_bytes.data(), keyToWrap_bytes.size()) != 1) {
                throw std::runtime_error("EVP_EncryptUpdate failed");
            }
            
            int finallen = 0;
            if (EVP_EncryptFinal_ex(ctx, wrappedKey_bytes.data() + outlen, &finallen) != 1) {
                throw std::runtime_error("EVP_EncryptFinal_ex failed");
            }

            wrappedKey_bytes.resize(outlen + finallen);
            finalPayload = hexEncode(wrappedKey_bytes.data(), wrappedKey_bytes.size());
            EVP_CIPHER_CTX_free(ctx);

        } else {
            std::cerr << "Error: Unknown wrapping algorithm '" << algorithm << "'." << std::endl;
            return false;
        }

    } catch (const std::exception& e) {
        std::cerr << "Crypto Error: " << e.what() << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    // 3. Save the wrapped key back to the vault
    childKey.publicKey = finalPayload; // Overwrite with ciphertext
    childKey.parentKey = parentKeyName;   // Log the parent
    
    // Re-save the child key file with the new encrypted data
    vault.saveKeyToFile(vault.storagePath + "/" + childKeyName, childKey);

    // 4. Update and save the log
    wrapLog[childKeyName] = algorithm;
    saveWrapLog();

    std::cout << "Successfully wrapped key '" << childKeyName << "' with '" 
              << parentKeyName << "' using " << algorithm << "." << std::endl;
    return true;
}


bool BaseCryptoProcessor::unwrapKey(const std::string& parentKeyName, const std::string& childKeyName) {
    // 1. Find algorithm from log
    if (wrapLog.find(childKeyName) == wrapLog.end()) {
        std::cerr << "Error: Key '" << childKeyName << "' not found in wrap log." << std::endl;
        return 0;
    }
    std::string algorithm = wrapLog[childKeyName];

    // 2. Get key data
    KeyData parentKey = vault.getKey(parentKeyName);
    KeyData childKey = vault.getKey(childKeyName);
    if (parentKey.keyName.empty() || childKey.keyName.empty()) {
        std::cerr << "Error: Parent or child key not found." << std::endl;
        return 0;
    }

    // 3. Get encrypted payload
    std::string payload = childKey.publicKey;
    std::vector<unsigned char> decryptedKey_bytes;

    try {
        if (algorithm == "AES-KWP") {
            if (parentKey.algorithm != "AES") throw std::runtime_error("Parent key is not AES");
            
            std::vector<unsigned char> wrapKey_bytes = hexDecode(parentKey.publicKey);
            std::vector<unsigned char> wrappedKey_bytes = hexDecode(payload);
            
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
            
            EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
            
            if (EVP_DecryptInit_ex(ctx, EVP_aes_256_wrap_pad(), NULL, wrapKey_bytes.data(), NULL) != 1) {
                throw std::runtime_error("EVP_DecryptInit_ex failed");
            }
            
            decryptedKey_bytes.resize(wrappedKey_bytes.size()); // Will be smaller
            int outlen = 0;
            
            if (EVP_DecryptUpdate(ctx, decryptedKey_bytes.data(), &outlen, wrappedKey_bytes.data(), wrappedKey_bytes.size()) != 1) {
                throw std::runtime_error("EVP_DecryptUpdate failed");
            }
            
            int finallen = 0;
            if (EVP_DecryptFinal_ex(ctx, decryptedKey_bytes.data() + outlen, &finallen) != 1) {
                throw std::runtime_error("EVP_DecryptFinal_ex failed (key tampering?)");
            }
            
            decryptedKey_bytes.resize(outlen + finallen);
            EVP_CIPHER_CTX_free(ctx);

        } else if (algorithm == "AES-KW") {
            if (parentKey.algorithm != "AES") throw std::runtime_error("Parent key is not AES");
            
            std::vector<unsigned char> wrapKey_bytes = hexDecode(parentKey.publicKey);
            std::vector<unsigned char> wrappedKey_bytes = hexDecode(payload);
            
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
            
            EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
            
            if (EVP_DecryptInit_ex(ctx, EVP_aes_256_wrap(), NULL, wrapKey_bytes.data(), NULL) != 1) {
                throw std::runtime_error("EVP_DecryptInit_ex failed");
            }
            
            // The decrypted key will be smaller than the wrapped key
            decryptedKey_bytes.resize(wrappedKey_bytes.size()); 
            int outlen = 0;
            
            if (EVP_DecryptUpdate(ctx, decryptedKey_bytes.data(), &outlen, wrappedKey_bytes.data(), wrappedKey_bytes.size()) != 1) {
                throw std::runtime_error("EVP_DecryptUpdate failed");
            }
            
            int finallen = 0;
            if (EVP_DecryptFinal_ex(ctx, decryptedKey_bytes.data() + outlen, &finallen) != 1) {
                throw std::runtime_error("EVP_DecryptFinal_ex failed (key tampering?)");
            }
            
            decryptedKey_bytes.resize(outlen + finallen);
            EVP_CIPHER_CTX_free(ctx);

        } else {
            std::cerr << "Error: Unknown wrapping algorithm '" << algorithm << "' in log." << std::endl;
            return 0;
        }

    } catch (const std::exception& e) {
        std::cerr << "Crypto Error: " << e.what() << std::endl;
        ERR_print_errors_fp(stderr);
        return 0;
    }

    // 4. Return the hex-encoded plaintext key
    std::cout << "Successfully unwrapped key '" << childKeyName << "'." << std::endl;

        // 3. Save the wrapped key back to the vault
    childKey.publicKey = hexEncode(decryptedKey_bytes.data(), decryptedKey_bytes.size()); // Overwrite with ciphertext
    childKey.parentKey = parentKeyName;   // Log the parent
    
    // Re-save the child key file with the new encrypted data
    vault.saveKeyToFile(vault.storagePath + "/" + childKeyName, childKey);

    return 1;
}

std::string BaseCryptoProcessor::encrypt(const std::string& parentKeyName , const std::string& childKey , const std::string& algorithm) {

    KeyData parentKey = vault.getKey(parentKeyName);
    if (parentKey.keyName.empty() ) {
        std::cerr << "Error: Parent  not found." << std::endl;
        return "";
    }

    // 2. Get the key material to wrap (child's private key)
    std::vector<unsigned char> keyToWrap_bytes = hexDecode(childKey);
    std::vector<unsigned char> wrappedKey_bytes;
    std::string finalPayload; // This will be saved as the new "publicKey"

    try {
        if (algorithm == "AES-KWP") {
            if (parentKey.algorithm != "AES") {
                std::cerr << "Error: AES-KWP requires an AES parent key." << std::endl;
                return "";
            }
            std::vector<unsigned char> wrapKey_bytes = hexDecode(parentKey.publicKey);

            // AES-KWP uses AES-256-WRAP-PAD cipher
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
            
            // Allow wrapping
            EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
            
            if (EVP_EncryptInit_ex(ctx, EVP_aes_256_wrap_pad(), NULL, wrapKey_bytes.data(), NULL) != 1) {
                throw std::runtime_error("EVP_EncryptInit_ex failed");
            }
            
            // Resize buffer to be slightly larger
            wrappedKey_bytes.resize(keyToWrap_bytes.size() + 16); 
            int outlen = 0;
            
            if (EVP_EncryptUpdate(ctx, wrappedKey_bytes.data(), &outlen, keyToWrap_bytes.data(), keyToWrap_bytes.size()) != 1) {
                throw std::runtime_error("EVP_EncryptUpdate failed");
            }
            
            int finallen = 0;
            if (EVP_EncryptFinal_ex(ctx, wrappedKey_bytes.data() + outlen, &finallen) != 1) {
                throw std::runtime_error("EVP_EncryptFinal_ex failed");
            }

            wrappedKey_bytes.resize(outlen + finallen);
            finalPayload = hexEncode(wrappedKey_bytes.data(), wrappedKey_bytes.size());
            EVP_CIPHER_CTX_free(ctx);

        } else if (algorithm == "AES-KW") {
            if (parentKey.algorithm != "AES") {
                std::cerr << "Error: AES-KW requires an AES parent key." << std::endl;
                return "";
            }
            // RFC 3394 requires key data to be a multiple of 8 bytes
            if (keyToWrap_bytes.size() % 8 != 0) {
                std::cerr << "Error: AES-KW (RFC 3394) requires key data to be a multiple of 8 bytes." << std::endl;
                return "";
            }
            std::vector<unsigned char> wrapKey_bytes = hexDecode(parentKey.publicKey);

            // AES-KW uses AES-256-WRAP cipher (no padding)
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
            
            EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
            
            if (EVP_EncryptInit_ex(ctx, EVP_aes_256_wrap(), NULL, wrapKey_bytes.data(), NULL) != 1) {
                throw std::runtime_error("EVP_EncryptInit_ex failed");
            }
            
            // Output size for AES-KW is input size + 8 bytes (for the IV)
            wrappedKey_bytes.resize(keyToWrap_bytes.size() + 8); 
            int outlen = 0;
            
            if (EVP_EncryptUpdate(ctx, wrappedKey_bytes.data(), &outlen, keyToWrap_bytes.data(), keyToWrap_bytes.size()) != 1) {
                throw std::runtime_error("EVP_EncryptUpdate failed");
            }
            
            int finallen = 0;
            if (EVP_EncryptFinal_ex(ctx, wrappedKey_bytes.data() + outlen, &finallen) != 1) {
                throw std::runtime_error("EVP_EncryptFinal_ex failed");
            }

            wrappedKey_bytes.resize(outlen + finallen);
            finalPayload = hexEncode(wrappedKey_bytes.data(), wrappedKey_bytes.size());
            EVP_CIPHER_CTX_free(ctx);

        } else if (algorithm == "RSA-OAEP") {
            if (parentKey.algorithm != "RSA") {
                std::cerr << "Error: RSA-OAEP requires an RSA parent key." << std::endl;
                return "";
            }
            EVP_PKEY* pkey = stringToPkey(parentKey.publicKey, false); // Use public key to encrypt
            if (!pkey) throw std::runtime_error("stringToPkey failed for RSA public key");

            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
            if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new failed");

            if (EVP_PKEY_encrypt_init(ctx) <= 0) throw std::runtime_error("EVP_PKEY_encrypt_init failed");
            if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
                throw std::runtime_error("EVP_PKEY_CTX_set_rsa_padding failed");
            }

            size_t outlen = 0;
            // First call to get required buffer size
            if (EVP_PKEY_encrypt(ctx, NULL, &outlen, keyToWrap_bytes.data(), keyToWrap_bytes.size()) <= 0) {
                throw std::runtime_error("EVP_PKEY_encrypt size check failed");
            }
            
            wrappedKey_bytes.resize(outlen);
            
            // Second call to actually encrypt
            if (EVP_PKEY_encrypt(ctx, wrappedKey_bytes.data(), &outlen, keyToWrap_bytes.data(), keyToWrap_bytes.size()) <= 0) {
                throw std::runtime_error("EVP_PKEY_encrypt failed");
            }

            wrappedKey_bytes.resize(outlen); // Adjust to actual size
            finalPayload = hexEncode(wrappedKey_bytes.data(), wrappedKey_bytes.size());
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);

        } else {
            std::cerr << "Error: Unknown wrapping algorithm '" << algorithm << "'." << std::endl;
            return "";
        }

    } catch (const std::exception& e) {
        std::cerr << "Crypto Error: " << e.what() << std::endl;
        ERR_print_errors_fp(stderr);
        return "";
    }

    std::cout << "Sucessfully encrypted " << childKey << " with  " << parentKeyName << std::endl;

   return finalPayload;


}
    




std::string BaseCryptoProcessor::decrypt(const std::string& parentKeyName , const std::string& childKey, const std::string& algorithm) {

    // 2. Get key data
    KeyData parentKey = vault.getKey(parentKeyName);
    if (parentKey.keyName.empty()) {
        std::cerr << "Error: Parent or child key not found." << std::endl;
        return 0;
    }

    // 3. Get encrypted payload
    std::string payload = childKey;
    std::vector<unsigned char> decryptedKey_bytes;

    std::cout << "decoding" << payload << std::endl;

    try {
        if (algorithm == "AES-KWP") {
            if (parentKey.algorithm != "AES") throw std::runtime_error("Parent key is not AES");
            
            std::vector<unsigned char> wrapKey_bytes = hexDecode(parentKey.publicKey);
            std::vector<unsigned char> wrappedKey_bytes = hexDecode(payload);
            
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
            
            EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
            
            if (EVP_DecryptInit_ex(ctx, EVP_aes_256_wrap_pad(), NULL, wrapKey_bytes.data(), NULL) != 1) {
                throw std::runtime_error("EVP_DecryptInit_ex failed");
            }
            
            decryptedKey_bytes.resize(wrappedKey_bytes.size()); // Will be smaller
            int outlen = 0;
            
            if (EVP_DecryptUpdate(ctx, decryptedKey_bytes.data(), &outlen, wrappedKey_bytes.data(), wrappedKey_bytes.size()) != 1) {
                throw std::runtime_error("EVP_DecryptUpdate failed");
            }
            
            int finallen = 0;
            if (EVP_DecryptFinal_ex(ctx, decryptedKey_bytes.data() + outlen, &finallen) != 1) {
                throw std::runtime_error("EVP_DecryptFinal_ex failed (key tampering?)");
            }
            
            decryptedKey_bytes.resize(outlen + finallen);
            EVP_CIPHER_CTX_free(ctx);

        } else if (algorithm == "AES-KW") {
            if (parentKey.algorithm != "AES") throw std::runtime_error("Parent key is not AES");
            
            std::vector<unsigned char> wrapKey_bytes = hexDecode(parentKey.publicKey);
            std::vector<unsigned char> wrappedKey_bytes = hexDecode(payload);
            
            EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
            if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
            
            EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
            
            if (EVP_DecryptInit_ex(ctx, EVP_aes_256_wrap(), NULL, wrapKey_bytes.data(), NULL) != 1) {
                throw std::runtime_error("EVP_DecryptInit_ex failed");
            }
            
            // The decrypted key will be smaller than the wrapped key
            decryptedKey_bytes.resize(wrappedKey_bytes.size()); 
            int outlen = 0;
            
            if (EVP_DecryptUpdate(ctx, decryptedKey_bytes.data(), &outlen, wrappedKey_bytes.data(), wrappedKey_bytes.size()) != 1) {
                throw std::runtime_error("EVP_DecryptUpdate failed");
            }
            
            int finallen = 0;
            if (EVP_DecryptFinal_ex(ctx, decryptedKey_bytes.data() + outlen, &finallen) != 1) {
                throw std::runtime_error("EVP_DecryptFinal_ex failed (key tampering?)");
            }
            
            decryptedKey_bytes.resize(outlen + finallen);
            EVP_CIPHER_CTX_free(ctx);

        } else if (algorithm == "RSA-OAEP") {
            if (parentKey.algorithm != "RSA") throw std::runtime_error("Parent key is not RSA");

            EVP_PKEY* pkey = stringToPkey(parentKey.privateKey, true); // Use private key to decrypt
            if (!pkey) throw std::runtime_error("stringToPkey failed for RSA private key");
            
            std::vector<unsigned char> wrappedKey_bytes = hexDecode(payload);

            EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
            if (!ctx) throw std::runtime_error("EVP_PKEY_CTX_new failed");

            if (EVP_PKEY_decrypt_init(ctx) <= 0) throw std::runtime_error("EVP_PKEY_decrypt_init failed");
            if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
                throw std::runtime_error("EVP_PKEY_CTX_set_rsa_padding failed");
            }

            size_t outlen = 0;
            if (EVP_PKEY_decrypt(ctx, NULL, &outlen, wrappedKey_bytes.data(), wrappedKey_bytes.size()) <= 0) {
                throw std::runtime_error("EVP_PKEY_decrypt size check failed");
            }
            
            decryptedKey_bytes.resize(outlen);
            
            if (EVP_PKEY_decrypt(ctx, decryptedKey_bytes.data(), &outlen, wrappedKey_bytes.data(), wrappedKey_bytes.size()) <= 0) {
                throw std::runtime_error("EVP_PKEY_decrypt failed");
            }

            decryptedKey_bytes.resize(outlen);
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(pkey);

        } else {
            std::cerr << "Error: Unknown wrapping algorithm '" << algorithm << "' in log." << std::endl;
            return 0;
        }

    } catch (const std::exception& e) {
        std::cerr << "Crypto Error: " << e.what() << std::endl;
        ERR_print_errors_fp(stderr);
        return 0;
    }

    std::cout << "Decoding Complete" << std::endl;
    return hexEncode(decryptedKey_bytes.data(), decryptedKey_bytes.size()); 
}
