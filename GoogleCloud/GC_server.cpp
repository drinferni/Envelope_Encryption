#include <iostream>
#include <sstream>
#include <map>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "GCHSM.h"
#include "../HSM/AccessController.h"

// -------------------- Helpers --------------------
std::string makeJsonResponse(const std::string& status, const std::string& message,
                             const std::map<std::string,std::string>& data = {}) {
    std::ostringstream oss;
    oss << "{";
    oss << "\"status\":\"" << status << "\",";
    oss << "\"message\":\"" << message << "\"";
    for (const auto& p : data) {
        oss << ",\"" << p.first << "\":\"" << p.second << "\"";
    }
    oss << "}";
    return oss.str();
}

// Simple key-value JSON parser
std::map<std::string, std::string> parseSimpleJson(const std::string &s) {
    std::map<std::string, std::string> out;
    bool inKey = true;
    std::string key, val;
    bool inStr = false;
    char delim = '"';
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (c == '{' || c == '}' || c == ',') continue;
        if (c == '"' && !inStr) { inStr = true; continue; }
        if (c == '"' && inStr) { inStr = false; 
            if (inKey) { inKey = false; } else { out[key] = val; key.clear(); val.clear(); inKey = true; } 
            continue;
        }
        if (inStr) {
            if (inKey) key.push_back(c); 
            else val.push_back(c);
        } else if (c == ':') continue;
        else if (!inKey) val.push_back(c);
    }
    return out;
}

// Read a line from SSL
std::string ssl_read_line(SSL* ssl) {
    std::string line;
    char c;
    while (SSL_read(ssl, &c, 1) == 1) {
        if (c == '\n') break;
        line.push_back(c);
    }
    return line;
}

// -------------------- Client Handler --------------------
void handle_client(SSL* ssl, AccessController &ac, GCHSM &hsm) {
    if (!ssl) return;
    if (SSL_accept(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return;
    }

    std::string req = ssl_read_line(ssl);
    if (req.empty()) {
        SSL_write(ssl, makeJsonResponse("error","empty request").c_str(), 30);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return;
    }

    auto kv = parseSimpleJson(req);
    std::string username = kv.count("username") ? kv["username"] : "";
    std::string password = kv.count("password") ? kv["password"] : "";
    std::string action   = kv.count("action")   ? kv["action"]   : "";
    std::string keyname  = kv.count("keyname")  ? kv["keyname"]  : "";
    std::string childKey = kv.count("childKey") ? kv["childKey"] : "";
    std::string algo     = kv.count("algo")     ? kv["algo"]     : "";

    if (!ac.authenticate(username, password)) {
        std::string resp = makeJsonResponse("error", "authentication failed");
        SSL_write(ssl, resp.c_str(), resp.size());
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return;
    }

    try {
        if (action == "generateCryptoKey") {
            std::string wrapAlgo;
            bool ok = hsm.generateCryptoKey(username, keyname, algo, wrapAlgo);
            std::string resp = ok ? makeJsonResponse("ok", "CryptoKey generated",{ {"wrapAlgo",wrapAlgo} }) 
                                  : makeJsonResponse("error", "generateCryptoKey failed");
            SSL_write(ssl, resp.c_str(), resp.size());
        } else if (action == "encrypt") {
            std::string cipher = hsm.encrypt(username, keyname, childKey);
            std::string resp = cipher.empty() ? makeJsonResponse("error","encrypt failed")
                                              : makeJsonResponse("ok","encrypted",{ {"ciphertext",cipher} });
            SSL_write(ssl, resp.c_str(), resp.size());
        } else if (action == "decrypt") {
            std::string plain = hsm.decrypt(username, keyname, childKey);
            std::string resp = plain.empty() ? makeJsonResponse("error","decrypt failed")
                                            : makeJsonResponse("ok","decrypted",{ {"plaintext",plain} });
            SSL_write(ssl, resp.c_str(), resp.size());
        } else if (action == "canUserAccessCryptoKey") {
            bool ok = hsm.canUserAccessCryptoKey(username,keyname);
            std::string resp = makeJsonResponse("ok", "check result",{ {"allowed", ok ? "true":"false"} });
            SSL_write(ssl, resp.c_str(), resp.size());
        } else if (action == "grantCryptoKeyAccess") {
            bool ok = hsm.grantCryptoKeyAccess(username,keyname);
            std::string resp = makeJsonResponse("ok", ok ? "access granted" : "grant failed");
            SSL_write(ssl, resp.c_str(), resp.size());
        } else if (action == "getCryptoKeysForUser") {
            auto keys = hsm.getCryptoKeysForUser(username);
            std::ostringstream oss;
            for (size_t i=0;i<keys.size();++i) { if(i>0) oss << ","; oss << keys[i]; }
            std::string resp = makeJsonResponse("ok","keys",{ {"cryptoKeys",oss.str()} });
            SSL_write(ssl, resp.c_str(), resp.size());
        } else {
            std::string resp = makeJsonResponse("error","unknown action");
            SSL_write(ssl, resp.c_str(), resp.size());
        }
    } catch (const std::exception &ex) {
        std::string resp = makeJsonResponse("error", std::string("exception: ") + ex.what());
        SSL_write(ssl, resp.c_str(), resp.size());
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
}

// -------------------- Main Server --------------------
int main() {
    int port = 8443;
    KeyVault vault("./KeyLocker");
    GCHSM hsm(vault,"user_crypto.tsv");
    AccessController ac("passwords.tsv","users.tsv");

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) return 1;

    SSL_CTX_use_certificate_file(ctx,"server.crt",SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx,"server.key",SSL_FILETYPE_PEM);

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    bind(sock,(struct sockaddr*)&addr,sizeof(addr));
    listen(sock,5);

    std::cout << "GCHSM server listening on port " << port << "\n";

    while(true) {
        int client = accept(sock,nullptr,nullptr);
        if(client<0) continue;
        SSL* ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);
        handle_client(ssl,ac,hsm);
        close(client);
    }

    SSL_CTX_free(ctx);
    return 0;
}
