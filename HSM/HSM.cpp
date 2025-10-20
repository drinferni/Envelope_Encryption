// src/main.cpp
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <stdexcept>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <fstream>

// OpenSSL Headers
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>

// Project Headers
#include <include/json.hpp>
#include "AccessController.h"
#include "KeyVault.h"
#include "KeylifecycleManager.h"
#include "EnvelopeEncryptionManager.h"

using json = nlohmann::json;

// --- Global variables for cleanup ---
SSL_CTX *g_ctx = nullptr;
int g_server_fd = -1;

// --- Forward Declarations ---
bool generate_self_signed_cert();
void handle_client(SSL* ssl, AccessController& ac, KeyLifecycleManager& klm, EnvelopeEncryptionManager& eem);

// --- Certificate Generation ---

// Checks if certificate and key files exist.
bool certificates_exist() {
    std::ifstream cert_file("server.crt");
    std::ifstream key_file("server.key");
    return cert_file.good() && key_file.good();
}

// Programmatically generates a self-signed RSA certificate.
bool generate_self_signed_cert() {
    std::cout << "Generating new self-signed certificate and private key..." << std::endl;
    int ret = 0;
    int bits = 4096;
    unsigned long e = RSA_F4;

    // 1. Create EVP_PKEY structure for the new key
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pkey(EVP_PKEY_new(), &EVP_PKEY_free);
    if (!pkey) return false;

    // 2. Generate the RSA key
    std::unique_ptr<RSA, decltype(&RSA_free)> rsa(RSA_new(), &RSA_free);
    std::unique_ptr<BIGNUM, decltype(&BN_free)> bn(BN_new(), &BN_free);
    if (!rsa || !bn || !BN_set_word(bn.get(), e)) return false;

    if (!RSA_generate_key_ex(rsa.get(), bits, bn.get(), NULL)) return false;
    if (!EVP_PKEY_assign_RSA(pkey.get(), rsa.release())) return false; // pkey now owns rsa

    // 3. Create the X509 certificate
    std::unique_ptr<X509, decltype(&X509_free)> x509(X509_new(), &X509_free);
    if (!x509) return false;

    ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(x509.get()), 0); // Valid from now
    X509_gmtime_adj(X509_getm_notAfter(x509.get()), 31536000L); // Valid for 1 year

    X509_set_pubkey(x509.get(), pkey.get());

    // 4. Set subject and issuer name (self-signed)
    X509_NAME *name = X509_get_subject_name(x509.get());
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)"localhost", -1, -1, 0);
    X509_set_issuer_name(x509.get(), name);

    // 5. Sign the certificate with the private key
    if (!X509_sign(x509.get(), pkey.get(), EVP_sha256())) return false;

    // 6. Write private key and certificate to files
    std::unique_ptr<BIO, decltype(&BIO_free)> key_bio(BIO_new_file("server.key", "w+"), &BIO_free);
    if (!key_bio) return false;
    ret = PEM_write_bio_PrivateKey(key_bio.get(), pkey.get(), NULL, NULL, 0, NULL, NULL);
    if (!ret) return false;

    std::unique_ptr<BIO, decltype(&BIO_free)> cert_bio(BIO_new_file("server.crt", "w+"), &BIO_free);
    if (!cert_bio) return false;
    ret = PEM_write_bio_X509(cert_bio.get(), x509.get());
    if (!ret) return false;
    
    std::cout << "Successfully created server.key and server.crt." << std::endl;
    return true;
}


// --- Server Logic ---

// Function to initialize the OpenSSL server context
SSL_CTX* create_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

// Function to configure the context with certificate and key
void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "server.crt", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_private_key_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

// Function to handle a single client's request
void handle_client(SSL* ssl, AccessController& ac, KeyLifecycleManager& klm, EnvelopeEncryptionManager& eem) {
    char buffer[4096];
    std::string request_str;

    // Read until we have a complete JSON object
    int brace_count = 0;
    bool in_string = false;
    do {
        int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes <= 0) {
            int err = SSL_get_error(ssl, bytes);
            if (err == SSL_ERROR_ZERO_RETURN || err == SSL_ERROR_SYSCALL) {
                std::cout << "Client disconnected." << std::endl;
            } else {
                std::cerr << "SSL read error." << std::endl;
                ERR_print_errors_fp(stderr);
            }
            return;
        }
        buffer[bytes] = '\0';
        request_str.append(buffer);

        // Simple brace counting to find end of JSON object
        for (char c : std::string(buffer, bytes)) {
            if (c == '"') in_string = !in_string;
            if (!in_string) {
                if (c == '{') brace_count++;
                else if (c == '}') brace_count--;
            }
        }
    } while (brace_count > 0);
    
    std::cout << "Received Request:\n" << request_str << std::endl;

    json response;
    try {
        json request = json::parse(request_str);
        std::string command = request.at("command");
        std::string user = request.at("user");
        json params = request.value("params", json::object());

        if (command == "create_key") {
            if (!ac.can_perform(user, "CREATE_KEY")) throw std::runtime_error("Access Denied");
            std::string key_id = params.at("key_id");
            if (klm.create_key(key_id, "AES-256-GCM")) {
                response = {{"status", "success"}, {"message", "Key '" + key_id + "' created."}};
            } else {
                throw std::runtime_error("Failed to create key.");
            }
        } else if (command == "encrypt") {
            if (!ac.can_perform(user, "ENCRYPT")) throw std::runtime_error("Access Denied");
            std::string key_id = params.at("key_id");
            std::string data_str = params.at("data");
            std::vector<unsigned char> plaintext(data_str.begin(), data_str.end());
            std::string bundle;
            if (eem.encrypt(key_id, plaintext, bundle)) {
                response = {{"status", "success"}, {"data", {{"bundle", bundle}}}};
            } else {
                throw std::runtime_error("Encryption failed.");
            }
        } else if (command == "decrypt") {
            if (!ac.can_perform(user, "DECRYPT")) throw std::runtime_error("Access Denied");
            std::string bundle = params.at("bundle");
            std::vector<unsigned char> plaintext;
            if (eem.decrypt(bundle, plaintext)) {
                 response = {{"status", "success"}, {"data", {{"plaintext", std::string(plaintext.begin(), plaintext.end())}}}};
            } else {
                throw std::runtime_error("Decryption failed.");
            }
        } else {
            throw std::runtime_error("Unknown command: " + command);
        }

    } catch (const std::exception& e) {
        response = {{"status", "error"}, {"message", e.what()}};
    }
    
    std::string response_str = response.dump();
    SSL_write(ssl, response_str.c_str(), response_str.length());
}

// Cleanup function for signal handling
void cleanup(int sig) {
    std::cout << "\nShutting down server..." << std::endl;
    if (g_ctx) SSL_CTX_free(g_ctx);
    if (g_server_fd != -1) close(g_server_fd);
    exit(0);
}

int main() {
    // --- Configuration ---
    const char* master_pass_env = std::getenv("HSM_MASTER_PASSWORD");
    if (!master_pass_env) {
        std::cerr << "Error: HSM_MASTER_PASSWORD environment variable not set." << std::endl;
        return 1;
    }
    std::string master_password(master_pass_env);
    int port = 8443;

    // --- Initialize HSM Modules ---
    AccessController access_controller("./policies.json");
    KeyVault key_vault("./vault", master_password);
    KeyLifecycleManager lifecycle_manager(key_vault);
    EnvelopeEncryptionManager envelope_manager(key_vault);

    // --- Initialize OpenSSL & Check for Certificates ---
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    
    if (!certificates_exist()) {
        if (!generate_self_signed_cert()) {
            std::cerr << "Fatal: Failed to generate self-signed certificate." << std::endl;
            ERR_print_errors_fp(stderr);
            return EXIT_FAILURE;
        }
    }
    
    g_ctx = create_context();
    configure_context(g_ctx);

    // --- Setup Server Socket ---
    g_server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (g_server_fd < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }
    
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(g_server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(g_server_fd, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    // --- Register Signal Handler for graceful shutdown ---
    signal(SIGINT, cleanup);

    std::cout << "HSM Server listening on port " << port << std::endl;
    while (true) {
        sockaddr_in client_addr;
        uint len = sizeof(client_addr);
        int client_fd = accept(g_server_fd, (struct sockaddr*)&client_addr, &len);
        if (client_fd < 0) {
            perror("Unable to accept");
            continue;
        }
        
        std::cout << "Client connected." << std::endl;

        SSL *ssl = SSL_new(g_ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            handle_client(ssl, access_controller, lifecycle_manager, envelope_manager);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    // Cleanup (in practice, reached via signal handler)
    cleanup(0);
    return 0;
}