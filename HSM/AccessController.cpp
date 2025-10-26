#include "AccessController.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <iostream>
// No need for <openssl/sha.h> as EVP is now used

AccessController::AccessController(const std::string& passwordFile, const std::string& userFile) {
    loadPasswords(passwordFile);
    loadUsers(userFile);
}

void AccessController::loadPasswords(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open password file: " + filename);
    }
    std::string line;
    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string username, hash;
        if (std::getline(ss, username, '\t') && std::getline(ss, hash)) {
            passwordHashes[username] = hash;
        }
    }
    std::cout << "Loagged all the passwords from " << filename << std::endl;
}

void AccessController::loadUsers(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open user permissions file: " + filename);
    }
    std::string line;
    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string username, permission;
        if (std::getline(ss, username, '\t')) {
            while (std::getline(ss, permission, '\t')) {
                userPermissions[username].push_back(permission);
            }
        }
    }
    std::cout << "Loaded all the users" << std::endl;
}

std::string AccessController::hashPassword(const std::string& password) const {
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

    std::cout << "Hashing password" << std::endl;
    return ss.str();

}

bool AccessController::authenticate(const std::string& username, const std::string& password) const {

    std::cout << "Authentication :" << username << std::endl;

    if (passwordHashes.find(username) == passwordHashes.end()) {
        return false;
    }
    return passwordHashes.at(username) == hashPassword(password);
}

bool AccessController::authorize(const std::string& username, const std::string& operation) const {
    if (userPermissions.find(username) == userPermissions.end()) {
        return false;
    }
    const auto& perms = userPermissions.at(username);
    for (const auto& p : perms) {
        if (p == operation) {
            return true;
        }
    }
    return false;
}

