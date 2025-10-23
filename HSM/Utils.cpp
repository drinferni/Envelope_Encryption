#include <iostream>
#include <fstream>      // For file I/O (std::ifstream, std::ofstream)
#include <sstream>      // For string streams (std::stringstream)
#include <filesystem>   // For directory and file operations (C++17)
#include <iomanip>      // For std::setw, std::hex, std::setfill
#include <vector>

// --- OpenSSL Includes ---
// We use the modern EVP (Envelope) API for key generation
#include <openssl/evp.h>
#include <openssl/pem.h>     // For writing keys to PEM format
#include <openssl/bio.h>     // For in-memory I/O
#include <openssl/rand.h>    // For generating AES key
#include <openssl/err.h>     // For error reporting/


/**
 * @brief Encodes a raw byte buffer into a hex string.
 */
inline std::string hexEncode(const unsigned char* bytes, size_t len) {
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
inline std::vector<unsigned char> hexDecode(const std::string& hexStr) {
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hexStr.length(); i += 2) {
        std::string byteString = hexStr.substr(i, 2);
        unsigned char byte = (unsigned char)strtol(byteString.c_str(), NULL, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

/**
 * @brief Helper to load a PEM string (public or private) into an EVP_PKEY.
 */
inline EVP_PKEY* stringToPkey(const std::string& pem, bool isPrivate) {
    BIO* bio = BIO_new_mem_buf(pem.c_str(), -1);
    if (!bio) {
        std::cerr << "Error: BIO_new_mem_buf failed." << std::endl;
        return NULL;
    }

    EVP_PKEY* pkey = NULL;
    if (isPrivate) {
        pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    } else {
        pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
    }

    if (!pkey) {
        std::cerr << "Error: PEM_read_bio_... failed." << std::endl;
        ERR_print_errors_fp(stderr);
    }

    BIO_free(bio);
    return pkey;
}

/**
 * @brief Helper to serialize a public EVP_PKEY to a PEM string.
 * (Needed for ECDH ephemeral key)
 */
inline std::string pkeyToString_public(EVP_PKEY *pkey) {
    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        std::cerr << "Error: OpenSSL BIO_new failed." << std::endl;
        return "";
    }
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


/**
 * @brief Generates a 256-bit (32-byte) AES key and returns it as a hex string.
 */
inline std::string generateAESKey() {
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
inline std::string pkeyToString_private(EVP_PKEY *pkey) {
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
