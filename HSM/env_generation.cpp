#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <cstdlib> // For system()

// OpenSSL headers for hashing
#include <openssl/evp.h>

// For creating directories
#include <sys/stat.h>

// Hashes a password using SHA-256. This is the same modern implementation
// used by the AccessController to ensure hashes are compatible.
std::string hashPassword(const std::string& password) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    md = EVP_sha256();
    mdctx = EVP_MD_CTX_new();

    if (mdctx == NULL) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    if (1 != EVP_DigestUpdate(mdctx, password.c_str(), password.size())) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }

    if (1 != EVP_DigestFinal_ex(mdctx, hash, &hash_len)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    EVP_MD_CTX_free(mdctx);

    std::stringstream ss;
    for (unsigned int i = 0; i < hash_len; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}


int main() {
    std::cout << "HSM Environment Setup Utility" << std::endl;
    std::cout << "-----------------------------" << std::endl;

    // 2. Define users and create passwords.tsv
    std::cout << "[2/4] Creating passwords.tsv..." << std::endl;
    try {
        std::ofstream pass_file("passwords.tsv");
        if (!pass_file.is_open()) {
            throw std::runtime_error("Could not open passwords.tsv for writing.");
        }
        
        // Admin user, password is 'admin'
        pass_file << "admin" << "\t" << hashPassword("admin") << std::endl;
        // Standard user, password is 'user1'
        pass_file << "user1" << "\t" << hashPassword("user1") << std::endl;
        
        pass_file.close();
        std::cout << "      -> Success. Default users created (admin:admin, user1:user1)." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "      -> Error: " << e.what() << std::endl;
        return 1;
    }

    // 3. Create users.tsv with permissions
    std::cout << "[3/4] Creating users.tsv..." << std::endl;
    std::ofstream user_file("users.tsv");
    if (!user_file.is_open()) {
        std::cerr << "      -> Error: Could not open users.tsv for writing." << std::endl;
        return 1;
    }
    // Admin has all permissions
    user_file << "admin" << "\t" << "create-key" << "\t" << "encrypt" << "\t" << "decrypt" << "\t" << "sign" << std::endl;
    // User1 has encrypt and decrypt permissions
    user_file << "user1" << "\t" << "encrypt" << "\t" << "decrypt" << std::endl;
    user_file.close();
    std::cout << "      -> Success. Default permissions assigned." << std::endl;

    std::cout << "\nEnvironment setup complete!" << std::endl;

    return 0;
}
