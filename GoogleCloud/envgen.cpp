#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

// -------------------- Helper: SHA256 Hash --------------------
std::string hashPassword(const std::string &password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(password.c_str()), password.size(), hash);
    std::ostringstream oss;
    oss << std::hex;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        oss.width(2);
        oss.fill('0');
        oss << static_cast<int>(hash[i]);
    }
    return oss.str();
}

// -------------------- Write TSV --------------------
void writePasswordFile(const std::string &filename, const std::vector<std::pair<std::string,std::string>> &users) {
    std::ofstream ofs(filename);
    for (const auto &u : users) {
        ofs << u.first << "\t" << u.second << "\n";
    }
    ofs.close();
}

void writeUserPermissionsFile(const std::string &filename, const std::unordered_map<std::string,std::vector<std::string>> &users) {
    std::ofstream ofs(filename);
    for (const auto &kv : users) {
        ofs << kv.first;
        for (const auto &perm : kv.second) {
            ofs << "\t" << perm;
        }
        ofs << "\n";
    }
    ofs.close();
}

// -------------------- Generate Self-Signed Cert --------------------
bool generateSelfSignedCert(const std::string &certFile, const std::string &keyFile) {
    bool success = false;

    EVP_PKEY* pkey = nullptr;
    X509* x509 = nullptr;

    do {
        // 1. Generate RSA key
        pkey = EVP_PKEY_new();
        if (!pkey) break;

        RSA* rsa = RSA_new();
        BIGNUM* bn = BN_new();
        if (!rsa || !bn) break;
        BN_set_word(bn, RSA_F4);
        if (!RSA_generate_key_ex(rsa, 2048, bn, nullptr)) break;
        EVP_PKEY_assign_RSA(pkey, rsa);
        BN_free(bn);

        // 2. Generate X509 certificate
        x509 = X509_new();
        if (!x509) break;

        ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
        X509_gmtime_adj(X509_get_notBefore(x509), 0);
        X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // 1 year
        X509_set_pubkey(x509, pkey);

        X509_NAME* name = X509_get_subject_name(x509);
        X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC,
                                   (unsigned char*)"IN", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC,
                                   (unsigned char*)"AWSHSM_Sim", -1, -1, 0);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   (unsigned char*)"localhost", -1, -1, 0);
        X509_set_issuer_name(x509, name);

        if (!X509_sign(x509, pkey, EVP_sha256())) break;

        // Write private key
        FILE* fkey = fopen(keyFile.c_str(), "wb");
        if (!fkey) break;
        PEM_write_PrivateKey(fkey, pkey, nullptr, nullptr, 0, nullptr, nullptr);
        fclose(fkey);

        // Write certificate
        FILE* fcert = fopen(certFile.c_str(), "wb");
        if (!fcert) break;
        PEM_write_X509(fcert, x509);
        fclose(fcert);

        success = true;

    } while (false);

    if (x509) X509_free(x509);
    if (pkey) EVP_PKEY_free(pkey);

    return success;
}

// -------------------- Main --------------------
int main() {
    std::cout << "Generating SSL certificates...\n";
    if (!generateSelfSignedCert("server.crt", "server.key")) {
        std::cerr << "Failed to generate SSL certificate/key\n";
        return 1;
    }
    std::cout << "Generated server.crt and server.key\n";

    // Generate passwords.tsv
    std::cout << "Generating passwords.tsv...\n";
    std::vector<std::pair<std::string,std::string>> passwords = {
        {"alice", hashPassword("alice123")},
        {"bob", hashPassword("bob123")}
    };
    writePasswordFile("passwords.tsv", passwords);
    std::cout << "Generated passwords.tsv\n";

    // Generate users.tsv (permissions)
    std::cout << "Generating users.tsv...\n";
    std::unordered_map<std::string,std::vector<std::string>> userPerms;
    userPerms["alice"] = {"generateDataKey","generateDataKeyWithoutPlaintext","wrapKey","unwrapKey","listDeKs","generateCMK","getCmksForUser","getDeksForCmk","grantCmkAccess"};
    userPerms["bob"]   = {"generateDataKey","unwrapKey"};
    writeUserPermissionsFile("users.tsv", userPerms);
    std::cout << "Generated users.tsv\n";

    std::cout << "Environment generation complete.\n";
    return 0;
}
