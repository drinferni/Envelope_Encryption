#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <unordered_map>
#include <stdexcept>

// OpenSSL headers
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

// Networking headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include "HSM.h"

// --- Helper Functions ---

// Simple custom JSON parser to extract key-value pairs
std::unordered_map<std::string, std::string> parseJson(const std::string& json_str) {
    std::unordered_map<std::string, std::string> result;
    std::string key, value;
    bool in_key = false;
    bool in_value = false;
    bool in_string = false;
    std::string* current_buffer = nullptr;

    for (char c : json_str) {
        if (c == '"') {
            in_string = !in_string;
            if (in_string && !in_key && !in_value) {
                in_key = true;
                current_buffer = &key;
            } else if (!in_string && in_key) {
                // Key finished
            } else if (in_string && in_value) {
                current_buffer = &value;
            }
        } else if (c == ':' && in_key) {
            in_key = false;
            in_value = true;
        } else if (c == ',' || c == '}') {
            if (in_value) {
                result[key] = value;
                key.clear();
                value.clear();
                in_value = false;
            }
        } else if (in_string) {
            if (current_buffer) {
                *current_buffer += c;
            }
        }
    }
    return result;
}

// Simple JSON response builder
std::string createJsonResponse(const std::string& status, const std::string& message, const std::string& data) {
    return "{\"status\":\"" + status + "\",\"message\":\"" + message + "\",\"data\":\"" + data + "\"}";
}

// Base64 encoding
std::string base64_encode(const std::string &input) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, input.c_str(), input.length());
    BIO_flush(bio);

    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string encoded(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);

    return encoded;
}

// Base64 decoding
std::string base64_decode(const std::string &input) {
    BIO *bio, *b64;
    std::vector<char> buffer(input.length());

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(input.c_str(), -1);
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int decoded_length = BIO_read(bio, buffer.data(), buffer.size());
    BIO_free_all(bio);

    return std::string(buffer.data(), decoded_length);
}


// --- Server Setup ---

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int create_socket(int port) {
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }
    return s;
}

// --- Main Application Logic ---

void handle_request(HSM& hsm, SSL* ssl) {
    char buf[1024 * 8] = {0}; // 8K buffer for potentially large keys in requests
    int bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (bytes <= 0) {
        ERR_print_errors_fp(stderr);
        return;
    }
    buf[bytes] = '\0';
    
    std::string response;
    try {
        auto params = parseJson(buf);
        std::string command = params["command"];

        if (command.empty()) throw std::runtime_error("Missing 'command' field.");

        std::string username = params["username"];
        std::string password = params["password"];
        std::string keyName = params["key_name"];

        if (command == "create-key") {
            std::string algorithm = params["algorithm"];
            if (algorithm.empty()) throw std::runtime_error("Missing 'algorithm' (AES, RSA, EC).");
            if (hsm.createKey(username, password, keyName, algorithm)) {
                response = createJsonResponse("success", "Key created successfully.", "");
            } else {
                response = createJsonResponse("error", "Failed to create key.", "");
            }
        } else if (command == "encrypt") {
            std::string plaintext = base64_decode(params["data"]);
            std::string ciphertext = hsm.encrypt(username, password, keyName, plaintext);
            response = createJsonResponse("success", "Data encrypted.", base64_encode(ciphertext));
        } else if (command == "decrypt") {
            std::string ciphertext = base64_decode(params["data"]);
            std::string plaintext = hsm.decrypt(username, password, keyName, ciphertext);
            response = createJsonResponse("success", "Data decrypted.", base64_encode(plaintext));
        } else if (command == "sign") {
            std::string data_to_sign = base64_decode(params["data"]);
            std::string signature = hsm.sign(username, password, keyName, data_to_sign);
            response = createJsonResponse("success", "Data signed.", base64_encode(signature));
        } else if (command == "verify") {
            std::string data_to_verify = base64_decode(params["data"]);
            std::string signature = base64_decode(params["signature"]);
            bool isValid = hsm.verify(username, password, keyName, data_to_verify, signature);
            if (isValid) {
                response = createJsonResponse("success", "Signature is valid.", "");
            } else {
                response = createJsonResponse("error", "Signature is invalid.", "");
            }
        } else if (command == "tamper") {
            hsm.triggerTamperEvent();
            response = createJsonResponse("success", "Tamper event triggered. All keys zeroized.", "");
        } else {
            response = createJsonResponse("error", "Unknown command.", "");
        }
    } catch (const std::exception& e) {
        response = createJsonResponse("error", e.what(), "");
    }

    SSL_write(ssl, response.c_str(), response.length());
}


int main() {
    HSM hsm("passwords.tsv", "users.tsv", "KeyFolder");

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = create_context();
    configure_context(ctx);

    int sock = create_socket(8443);
    std::cout << "HSM Server listening on port 8443..." << std::endl;

    while (1) {
        struct sockaddr_in addr;
        unsigned int len = sizeof(addr);
        SSL *ssl;

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            continue;
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            std::cout << "Client connected." << std::endl;
            handle_request(hsm, ssl);
        }
        
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);
    }

    close(sock);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}

