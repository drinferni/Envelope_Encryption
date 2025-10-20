#include "HSM.h"
#include <stdexcept>

HSM::HSM(const std::string& passwordFile, const std::string& userFile, const std::string& keyStorePath)
    : accessController(passwordFile, userFile), keyVault(keyStorePath) {}

bool HSM::createKey(const std::string& username, const std::string& password, const std::string& keyName, const std::string& algorithm) {
    if (!accessController.authenticate(username, password)) {
        throw std::runtime_error("Authentication failed.");
    }
    if (!accessController.authorize(username, "create-key")) {
        throw std::runtime_error("Authorization failed for create-key.");
    }
    return keyVault.createKey(keyName, algorithm);
}

std::string HSM::encrypt(const std::string& username, const std::string& password, const std::string& keyName, const std::string& plaintext) {
    if (!accessController.authenticate(username, password)) {
        throw std::runtime_error("Authentication failed.");
    }
    if (!accessController.authorize(username, "encrypt")) {
        throw std::runtime_error("Authorization failed for encrypt.");
    }
    KeyData keyData = keyVault.getKey(keyName);
    if (keyData.algorithm != "AES") {
        throw std::runtime_error("Encrypt operation only supported for AES keys.");
    }
    return cryptoEngine.encrypt(plaintext, keyData.privateKey);
}

std::string HSM::decrypt(const std::string& username, const std::string& password, const std::string& keyName, const std::string& ciphertext) {
    if (!accessController.authenticate(username, password)) {
        throw std::runtime_error("Authentication failed.");
    }
    if (!accessController.authorize(username, "decrypt")) {
        throw std::runtime_error("Authorization failed for decrypt.");
    }
    KeyData keyData = keyVault.getKey(keyName);
    if (keyData.algorithm != "AES") {
        throw std::runtime_error("Decrypt operation only supported for AES keys.");
    }
    return cryptoEngine.decrypt(ciphertext, keyData.privateKey);
}

std::string HSM::sign(const std::string& username, const std::string& password, const std::string& keyName, const std::string& data) {
    if (!accessController.authenticate(username, password)) {
        throw std::runtime_error("Authentication failed.");
    }
    if (!accessController.authorize(username, "sign")) {
        throw std::runtime_error("Authorization failed for sign.");
    }
    KeyData keyData = keyVault.getKey(keyName);
    if (keyData.algorithm != "RSA" && keyData.algorithm != "EC") {
        throw std::runtime_error("Sign operation requires an asymmetric key (RSA or EC).");
    }
    return cryptoEngine.sign(data, keyData.privateKey);
}

bool HSM::verify(const std::string& username, const std::string& password, const std::string& keyName, const std::string& data, const std::string& signature) {
    if (!accessController.authenticate(username, password)) {
        throw std::runtime_error("Authentication failed.");
    }
    if (!accessController.authorize(username, "verify")) {
        throw std::runtime_error("Authorization failed for verify.");
    }
    KeyData keyData = keyVault.getKey(keyName);
    if (keyData.algorithm != "RSA" && keyData.algorithm != "EC") {
        throw std::runtime_error("Verify operation requires an asymmetric key (RSA or EC).");
    }
    return cryptoEngine.verify(data, signature, keyData.publicKey);
}

void HSM::triggerTamperEvent() {
    integrityMonitor.trigger(keyVault);
}

