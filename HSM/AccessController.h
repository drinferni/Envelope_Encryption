#ifndef ACCESS_CONTROLLER_H
#define ACCESS_CONTROLLER_H

#include <string>
#include <vector>
#include <unordered_map>
#include <openssl/sha.h>
#include <openssl/evp.h> // Added for modern hashing API

class AccessController {
public:
    AccessController(const std::string& passwordFile, const std::string& userFile);
    bool authenticate(const std::string& username, const std::string& password) const;
    bool authorize(const std::string& username, const std::string& operation) const;

private:
    void loadPasswords(const std::string& filename);
    void loadUsers(const std::string& filename);
    std::string hashPassword(const std::string& password) const;

    std::unordered_map<std::string, std::string> passwordHashes;
    std::unordered_map<std::string, std::vector<std::string>> userPermissions;
};

#endif // ACCESS_CONTROLLER_H

