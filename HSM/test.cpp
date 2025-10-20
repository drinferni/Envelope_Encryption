#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <stdexcept>
#include <memory>

// OpenSSL headers
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

// Networking headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

// --- Helper Functions ---

// Simple custom JSON parser to extract key-value pairs
std::unordered_map<std::string, std::string> parseJsonResponse(const std::string& json_str) {
    std::unordered_map<std::string, std::string> result;
    std::string key, value;
    bool in_key = false, in_value = false, in_string = false;
    std::string* current_buffer = nullptr;

    for (char c : json_str) {
        if (c == '"') {
            in_string = !in_string;
            if (in_string && !in_key && !in_value) { in_key = true; current_buffer = &key; }
            else if (!in_string && in_key) { /* Key finished */ }
            else if (in_string && in_value) { current_buffer = &value; }
        } else if (c == ':' && in_key) { in_key = false; in_value = true;
        } else if (c == ',' || c == '}') {
            if (in_value) {
                result[key] = value;
                key.clear(); value.clear();
                in_value = false;
            }
        } else if (in_string && current_buffer) { *current_buffer += c; }
    }
    return result;
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

// --- Test Client Class ---

class HsmClient {
public:
    HsmClient(const std::string& host, int port) {
        SSL_library_init();
        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();

        const SSL_METHOD *method = TLS_client_method();
        ctx = SSL_CTX_new(method);
        if (!ctx) {
            throw std::runtime_error("Unable to create SSL context");
        }

        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            throw std::runtime_error("Unable to create socket");
        }

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            throw std::runtime_error("Unable to connect to server");
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);

        if (SSL_connect(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
            throw std::runtime_error("SSL connection failed");
        }
    }

    ~HsmClient() {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        if (sock >= 0) {
            close(sock);
        }
        if (ctx) {
            SSL_CTX_free(ctx);
        }
    }

    std::unordered_map<std::string, std::string> sendRequest(const std::string& jsonRequest) {
        if (SSL_write(ssl, jsonRequest.c_str(), jsonRequest.length()) <= 0) {
            throw std::runtime_error("SSL_write failed");
        }

        char buf[1024 * 8] = {0};
        int bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
        if (bytes <= 0) {
            throw std::runtime_error("SSL_read failed");
        }
        buf[bytes] = '\0';
        return parseJsonResponse(buf);
    }

private:
    int sock = -1;
    SSL_CTX *ctx = nullptr;
    SSL *ssl = nullptr;
};

// --- Test Runner ---

void run_test(const std::string& test_name, bool (*test_func)(HsmClient&)) {
    std::cout << "-------------------------------------------\n";
    std::cout << "RUNNING TEST: " << test_name << std::endl;
    try {
        HsmClient client("127.0.0.1", 8443);
        if (test_func(client)) {
            std::cout << "RESULT: PASS" << std::endl;
        } else {
            std::cout << "RESULT: FAIL" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "ERROR: " << e.what() << std::endl;
        std::cout << "RESULT: FAIL" << std::endl;
    }
}

// --- Individual Test Cases ---

bool test_key_creation(HsmClient& client) {
    std::cout << "  Creating AES key..." << std::endl;
    auto res_aes = client.sendRequest("{\"command\":\"create-key\",\"username\":\"admin\",\"password\":\"admin\",\"key_name\":\"test_aes_key\",\"algorithm\":\"AES\"}");
    if (res_aes["status"] != "success") { std::cerr << "AES key creation failed.\n"; return false; }

    std::cout << "  Creating RSA key..." << std::endl;
    auto res_rsa = client.sendRequest("{\"command\":\"create-key\",\"username\":\"admin\",\"password\":\"admin\",\"key_name\":\"test_rsa_key\",\"algorithm\":\"RSA\"}");
    if (res_rsa["status"] != "success") { std::cerr << "RSA key creation failed.\n"; return false; }
    
    std::cout << "  Creating EC key..." << std::endl;
    auto res_ec = client.sendRequest("{\"command\":\"create-key\",\"username\":\"admin\",\"password\":\"admin\",\"key_name\":\"test_ec_key\",\"algorithm\":\"EC\"}");
    if (res_ec["status"] != "success") { std::cerr << "EC key creation failed.\n"; return false; }

    return true;
}

bool test_aes_encrypt_decrypt(HsmClient& client) {
    std::string plaintext = "This is a secret message for AES!";
    std::cout << "  Encrypting with AES key..." << std::endl;
    
    std::string req = "{\"command\":\"encrypt\",\"username\":\"user1\",\"password\":\"user1\",\"key_name\":\"test_aes_key\",\"data\":\"" + base64_encode(plaintext) + "\"}";
    auto res_enc = client.sendRequest(req);
    if (res_enc["status"] != "success") { std::cerr << "AES encryption failed.\n"; return false; }
    
    std::string ciphertext_b64 = res_enc["data"];
    std::cout << "  Decrypting with AES key..." << std::endl;
    
    req = "{\"command\":\"decrypt\",\"username\":\"user1\",\"password\":\"user1\",\"key_name\":\"test_aes_key\",\"data\":\"" + ciphertext_b64 + "\"}";
    auto res_dec = client.sendRequest(req);
    if (res_dec["status"] != "success") { std::cerr << "AES decryption failed.\n"; return false; }
    
    std::string decrypted_text = base64_decode(res_dec["data"]);
    if (plaintext != decrypted_text) {
        std::cerr << "Decrypted text does not match original plaintext!\n";
        return false;
    }
    std::cout << "  Decrypted text matches original. Success.\n";
    return true;
}

bool test_rsa_sign_verify(HsmClient& client) {
    std::string data = "This data will be signed by RSA.";
    std::cout << "  Signing data with RSA key..." << std::endl;

    std::string req = "{\"command\":\"sign\",\"username\":\"admin\",\"password\":\"admin\",\"key_name\":\"test_rsa_key\",\"data\":\"" + base64_encode(data) + "\"}";
    auto res_sign = client.sendRequest(req);
    if (res_sign["status"] != "success") { std::cerr << "RSA signing failed.\n"; return false; }

    std::string signature_b64 = res_sign["data"];
    
    // Test 1: Successful verification
    std::cout << "  Verifying correct signature..." << std::endl;
    req = "{\"command\":\"verify\",\"username\":\"user1\",\"password\":\"user1\",\"key_name\":\"test_rsa_key\",\"data\":\"" + base64_encode(data) + "\",\"signature\":\"" + signature_b64 + "\"}";
    auto res_verify_ok = client.sendRequest(req);
    if (res_verify_ok["status"] != "success") { std::cerr << "RSA verification failed for valid signature.\n"; return false; }
    std::cout << "  Verification successful.\n";
    
    // Test 2: Verification with wrong data
    std::cout << "  Verifying with wrong data (should fail)..." << std::endl;
    req = "{\"command\":\"verify\",\"username\":\"user1\",\"password\":\"user1\",\"key_name\":\"test_rsa_key\",\"data\":\"" + base64_encode("wrong data") + "\",\"signature\":\"" + signature_b64 + "\"}";
    auto res_verify_bad_data = client.sendRequest(req);
    if (res_verify_bad_data["status"] != "error") { std::cerr << "RSA verification succeeded with wrong data.\n"; return false; }
    std::cout << "  Verification failed as expected.\n";

    return true;
}


bool test_ec_sign_verify(HsmClient& client) {
    std::string data = "This data will be signed by Elliptic Curve.";
    std::cout << "  Signing data with EC key..." << std::endl;

    std::string req = "{\"command\":\"sign\",\"username\":\"admin\",\"password\":\"admin\",\"key_name\":\"test_ec_key\",\"data\":\"" + base64_encode(data) + "\"}";
    auto res_sign = client.sendRequest(req);
    if (res_sign["status"] != "success") { std::cerr << "EC signing failed.\n"; return false; }
    
    std::string signature_b64 = res_sign["data"];

    // Test 1: Successful verification
    std::cout << "  Verifying correct signature..." << std::endl;
    req = "{\"command\":\"verify\",\"username\":\"user1\",\"password\":\"user1\",\"key_name\":\"test_ec_key\",\"data\":\"" + base64_encode(data) + "\",\"signature\":\"" + signature_b64 + "\"}";
    auto res_verify_ok = client.sendRequest(req);
    if (res_verify_ok["status"] != "success") { std::cerr << "EC verification failed for valid signature.\n"; return false; }
    std::cout << "  Verification successful.\n";

    // Test 2: Verification with corrupted signature
    std::cout << "  Verifying with corrupted signature (should fail)..." << std::endl;
    std::string corrupted_sig_b64 = signature_b64;
    corrupted_sig_b64[5] = (corrupted_sig_b64[5] == 'A' ? 'B' : 'A'); // Flip a character
    req = "{\"command\":\"verify\",\"username\":\"user1\",\"password\":\"user1\",\"key_name\":\"test_ec_key\",\"data\":\"" + base64_encode(data) + "\",\"signature\":\"" + corrupted_sig_b64 + "\"}";
    auto res_verify_bad_sig = client.sendRequest(req);
    if (res_verify_bad_sig["status"] != "error") { std::cerr << "EC verification succeeded with a corrupted signature.\n"; return false; }
    std::cout << "  Verification failed as expected.\n";

    return true;
}


int main() {
    std::cout << "Starting HSM Test Suite...\n";
    std::cout << "Ensure the HSM server is running and the environment is set up.\n";
    
    run_test("Key Creation (AES, RSA, EC)", test_key_creation);
    run_test("AES Encrypt/Decrypt Cycle", test_aes_encrypt_decrypt);
    run_test("RSA Sign/Verify Cycle", test_rsa_sign_verify);
    run_test("EC Sign/Verify Cycle", test_ec_sign_verify);
    
    std::cout << "-------------------------------------------\n";
    std::cout << "Test Suite Finished.\n";

    return 0;
}
