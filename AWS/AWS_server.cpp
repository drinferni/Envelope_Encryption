// ssl_server.cpp
// Build: g++ ssl_server.cpp -o ssl_server -std=c++17 -lssl -lcrypto -lpthread
// Run: ./ssl_server server.crt server.key passwordFile usersFile user_cmk_map.txt cmk_dek_map.txt

#include <iostream>
#include <string>
#include <sstream>
#include <thread>
#include <vector>
#include <map>
#include <fstream>
#include <atomic>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <bits/socket.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>

#include "../HSM/AccessController.h" // header path must match your project (case-sensitive)
#include "AWSHSM.h"
#include "../HSM/KeyVault.h"   // adjust path if needed

// ---------- Simple (non-robust) JSON helper ----------
// This is a tiny parser sufficient for simple flat JSON objects:
// {"key":"value", "num":123, "flag": true}
std::map<std::string, std::string> parseSimpleJson(const std::string &s) {
    std::map<std::string, std::string> out;
    std::string key, value;
    bool parsingKey = true;   // true = key, false = value
    bool inQuotes = false;    // are we inside quotes
    std::string *target = &key;
    key = "";
    value = "";

    for (char c : s) {
        if (c == '{' || c == '}' || c == ' ' || c == '\n' || c == '\t') continue;

        if (c == '"') {
            inQuotes = !inQuotes;
            continue;
        }

        if (!inQuotes && c == ':') {
            parsingKey = false;
            target = &value;
            continue;
        }

        if (!inQuotes && c == ',') {
            out[key] = value;
            key.clear();
            value.clear();
            parsingKey = true;
            target = &key;
            continue;
        }

        target->push_back(c);
    }

    if (!key.empty() && !value.empty()) out[key] = value; // last pair
    return out;
}


static std::string makeJsonResponse(const std::string &status, const std::string &message,
                                    const std::map<std::string,std::string> &data = {}) {
    std::ostringstream ss;
    ss << "{";
    ss << "\"status\":\"" << status << "\",";
    ss << "\"message\":\"" << message << "\"";
    if (!data.empty()) {
        ss << ",\"data\":{";
        bool first = true;
        for (auto &kv : data) {
            if (!first) ss << ",";
            first = false;
            ss << "\"" << kv.first << "\":\"" << kv.second << "\"";
        }
        ss << "}";
    }
    ss << "}\n";
    return ss.str();
}

// ---------- SSL utilities ----------
static SSL_CTX* create_server_ctx(const char* cert_file, const char* key_file) {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        std::cerr << "Unable to create SSL context\n";
        return nullptr;
    }

    // Require TLS 1.2+
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_file(ctx, cert_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // Optional: require client cert? We assume username/password auth in JSON.
    return ctx;
}

// read until newline or EOF (simple framing)
static std::string ssl_read_line(SSL* ssl) {
    std::string out;
    char buf[1024];
    int n;
    while (true) {
        n = SSL_read(ssl, buf, sizeof(buf));
        if (n <= 0) break;
        out.append(buf, n);
        // if newline found, stop (assume client ends with \n)
        if (out.find('\n') != std::string::npos) break;
        // safety cap
        if (out.size() > 16*1024) break;
    }
    // trim after newline
    size_t pos = out.find('\n');
    if (pos != std::string::npos) out.resize(pos);
    return out;
}

// ---------- Connection handler ----------
void handle_client(SSL* ssl, AccessController &ac, AWSHSM &hsm) {
    if (!ssl) return;
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return;
    }

    std::string req = ssl_read_line(ssl);
    if (req.empty()) {
        SSL_write(ssl, makeJsonResponse("error", "empty request").c_str(), 20);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return;
    }

    std::cout << "Request : " << req << std::endl;

    auto kv = parseSimpleJson(req);

    std::string username = kv.count("username") ? kv["username"] : "";
    std::string password = kv.count("password") ? kv["password"] : "";
    std::string action   = kv.count("action")   ? kv["action"]   : "";
    std::string cmk      = kv.count("cmk")      ? kv["cmk"]      : "";
    std::string wrapAlg  = kv.count("wrap")     ? kv["wrap"]     : "AES-KWP";
    std::string dekAlg   = kv.count("dek")      ? kv["dek"]      : "AES";
    std::string childKey = kv.count("child")    ? kv["child"]    : "";
    std::string parentKey= kv.count("parent")   ? kv["parent"]   : "";

    // Authenticate
    if (!ac.authenticate(username, password)) {
        SSL_write(ssl, makeJsonResponse("error", "authentication failed").c_str(), 30);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return;
    }

    // Authorize
    if (!ac.authorize(username, action)) {
        SSL_write(ssl, makeJsonResponse("error", "not authorized for action").c_str(), 30);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return;
    }

    try {
        std::map<std::string,std::string> data;
        std::string resp;

        if (action == "generateDataKey") {
            DataKey dk = hsm.generateDataKey(username, cmk, wrapAlg, dekAlg);
            std::cout << dk.ciphertextHex << ' ' << dk.plaintextHex << std::endl;
            if (!dk.isValid()) resp = makeJsonResponse("error", "generateDataKey failed");
            else {
                data["plaintextHex"] = dk.plaintextHex;
                data["ciphertextHex"]= dk.ciphertextHex;
                resp = makeJsonResponse("ok", "generated data key", data);
            }

        } else if (action == "generateDataKeyWithoutPlaintext") {
            std::string cipher = hsm.generateDataKeyWithoutPlaintext(username, cmk, wrapAlg, dekAlg);
            if (cipher.empty()) resp = makeJsonResponse("error", "generateDataKeyWithoutPlaintext failed");
            else {
                data["ciphertextHex"] = cipher;
                resp = makeJsonResponse("ok", "generated ciphertext-only data key", data);
            }

        } else if (action == "unwrapKey") {
            std::string plain = hsm.unwrapKey(username, parentKey, childKey);
            if (plain.empty()) resp = makeJsonResponse("error", "unwrapKey failed");
            else { data["plaintextHex"] = plain; resp = makeJsonResponse("ok", "unwrapped", data); }

        } else if (action == "wrapKey") {
            bool ok = hsm.wrapKey(username, parentKey, childKey, wrapAlg);
            resp = ok ? makeJsonResponse("ok", "wrapped") : makeJsonResponse("error", "wrapKey failed");

        } else if (action == "listDeKs") {
            auto deks = hsm.getDeksForCmk(cmk);
            std::ostringstream o; bool first=true;
            for (auto &d: deks) { if(!first) o << ","; first=false; o<<d; }
            data["deks"] = o.str();
            resp = makeJsonResponse("ok", "deks listed", data);

        } else if (action == "canUserAccessCmk") {
            bool ok = hsm.canUserAccessCmk(username, cmk);
            data["access"] = ok ? "true" : "false";
            resp = makeJsonResponse("ok", "checked CMK access", data);

        } else if (action == "grantCmkAccess") {
            bool ok = hsm.grantCmkAccess(wrapAlg, cmk);
            resp = ok ? makeJsonResponse("ok", "granted CMK access") : makeJsonResponse("error", "grantCmkAccess failed");

        } else if (action == "getCmksForUser") {
            auto cmks = hsm.getCmksForUser(username);
            std::ostringstream o; bool first=true;
            for (auto &c: cmks) { if(!first) o << ","; first=false; o<<c; }
            data["cmks"] = o.str();
            resp = makeJsonResponse("ok", "cmks listed for user", data);

        } else if (action == "generateCMK") {
            bool ok = hsm.generateCMK(username, cmk, wrapAlg);
            resp = ok ? makeJsonResponse("ok", "generated CMK") : makeJsonResponse("error", "generateCMK failed");

        } else {
            resp = makeJsonResponse("error", "unknown action");
        }

        std::cout << "Response : " << resp << std::endl;

        SSL_write(ssl, resp.c_str(), resp.size());
    }
    catch (const std::exception &ex) {
        std::string resp = makeJsonResponse("error", std::string("exception: ") + ex.what());
        SSL_write(ssl, resp.c_str(), resp.size());
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
}

// ---------- Main ----------
int main(int argc, char **argv) {
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0] << " server.crt server.key passwordFile usersFile user_cmk_map.txt\n";
        return 1;
    }
    const char *certfile = argv[1];
    const char *keyfile  = argv[2];
    const char *passwordFile = argv[3];
    const char *usersFile = argv[4];
    const char *userCmkFile = argv[5];

    // Init OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = create_server_ctx(certfile, keyfile);
    if (!ctx) return 2;

    // Initialize access controller
    AccessController ac(passwordFile, usersFile);
    ac.loadPasswords(passwordFile);
    ac.loadUsers(usersFile);

    KeyVault kv("./KeyLocker"); 
    AWSHSM hsm(kv, std::string(userCmkFile));

    int port = 8443;
    int sockfd = -1;
    {

        struct sockaddr_in addr;
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) { perror("socket"); return 3; }
        int opt = 1;
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;
        if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) { perror("bind"); return 4; }
        if (listen(sockfd, SOMAXCONN) < 0) { perror("listen"); return 5; }
    }

    std::cout << "SSL server listening on port " << port << "\n";

    // Accept loop
    while (true) {
        struct sockaddr_in client_addr;
        socklen_t len = sizeof(client_addr);
        int client = accept(sockfd, (struct sockaddr*)&client_addr, &len);
        if (client < 0) { perror("accept"); continue; }

        // Create SSL object
        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        // spawn thread to handle (detaches)
        std::thread t([ssl, &ac, &hsm]() {
            handle_client(ssl, ac, hsm);
        });
        t.detach();
    }

    // never reached in this simple server
    close(sockfd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}
