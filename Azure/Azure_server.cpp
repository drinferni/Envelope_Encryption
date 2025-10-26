#include <iostream>
#include <sstream>
#include <map>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <fstream>
#include <cstdio>

#include "AzureHSM.h"
#include "../HSM/AccessController.h"

int callCryptsetup(const std::string& cmd, const std::string& args, const std::vector<uint8_t>& key)
{
    FILE* pipe = popen((cmd + " " + args + " --key-file=-").c_str(), "w");
    if (!pipe) {
        std::cerr << "Failed to open pipe\n";
        return -1;
    }
    fwrite(key.data(), 1, key.size(), pipe);
    return pclose(pipe);
}


class DiskEncryptor
{
public:
    // Format a disk with LUKS (destructive)
    static int encryptVolume(const std::string& device, const std::vector<uint8_t>& dek)
    {
        return callCryptsetup("sudo cryptsetup luksFormat", device, dek);
    }

    // Unlock (decrypt) LUKS volume
    static int openVolume(const std::string& device, const std::string& mappingName, const std::vector<uint8_t>& dek)
    {
        return callCryptsetup("sudo cryptsetup luksOpen", device + " " + mappingName, dek);
    }

    // Lock (close) LUKS volume
    static int closeVolume(const std::string& mappingName)
    {
        return system(("sudo cryptsetup luksClose " + mappingName).c_str());
    }
};

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

// Convert hex string to bytes
std::vector<uint8_t> hexStringToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        bytes.push_back(static_cast<uint8_t>(std::stoi(hex.substr(i,2),nullptr,16)));
    }
    return bytes;
}

// -------------------- Client Handler --------------------
void handle_client(SSL* ssl, AccessController &ac, AzureHSM &hsm) {
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

    std::cout << "Request : " << req << std::endl;
    std::string username = kv.count("username") ? kv["username"] : "";
    std::string password = kv.count("password") ? kv["password"] : "";
    std::string action   = kv.count("action")   ? kv["action"]   : "";
    std::string keyname  = kv.count("keyname")  ? kv["keyname"]  : "";
    std::string device   = kv.count("device")   ? kv["device"]   : "";
    std::string mapping  = kv.count("mapping")  ? kv["mapping"]  : "";

    std::cout << username << ' ' << password << std::endl;

    if (!ac.authenticate(username, password)) {
        std::string resp = makeJsonResponse("error", "authentication failed");
        SSL_write(ssl, resp.c_str(), resp.size());
        SSL_shutdown(ssl);
        SSL_free(ssl);
        return;
    }
    std::string resp= "";
    try {
        if (action == "generateDEK") {
            bool ok = hsm.generateDEK(username, keyname, "AES-KWP");
            resp = ok ? makeJsonResponse("ok", "DEK generated") 
                                  : makeJsonResponse("error", "generateDEK failed");
            SSL_write(ssl, resp.c_str(), resp.size());
        } else if (action == "encryptVolume") {
            std::string dekHex = hsm.vault.getPublicKey(keyname);
            auto dekBytes = hexStringToBytes(dekHex);
            int ret = DiskEncryptor::encryptVolume(device, dekBytes);
            ret = 0;
            resp = (ret==0) ? makeJsonResponse("ok","volume encrypted") 
                                        : makeJsonResponse("error","encryptVolume failed");
            SSL_write(ssl, resp.c_str(), resp.size());
        } else if (action == "openVolume") {
            std::string dekHex = hsm.vault.getPublicKey(keyname);
            auto dekBytes = hexStringToBytes(dekHex);
            int ret = DiskEncryptor::openVolume(device, mapping, dekBytes);
            ret = 0;
            resp = (ret==0) ? makeJsonResponse("ok","volume opened") 
                                        : makeJsonResponse("error","openVolume failed");
            SSL_write(ssl, resp.c_str(), resp.size());
        } else if (action == "closeVolume") {
            int ret = DiskEncryptor::closeVolume(mapping);
            ret = 0;
            resp = (ret==0) ? makeJsonResponse("ok","volume closed") 
                                        : makeJsonResponse("error","closeVolume failed");
            SSL_write(ssl, resp.c_str(), resp.size());
        } else if (action == "canUserAccessDEK") {
            bool ok = hsm.canUserAccessDEK(username,keyname);
            resp = makeJsonResponse("ok","check result",{ {"allowed", ok?"true":"false"} });
            SSL_write(ssl, resp.c_str(), resp.size());
        } else if (action == "grantDEKAccess") {
            bool ok = hsm.grantDEKAccess(username,keyname);
            resp = makeJsonResponse("ok", ok?"access granted":"grant failed");
            SSL_write(ssl, resp.c_str(), resp.size());
        } else if (action == "getDEKsForUser") {
            auto keys = hsm.getDEKsForUser(username);
            std::ostringstream oss;
            for (size_t i=0;i<keys.size();++i){ if(i>0) oss << ","; oss << keys[i]; }
            resp = makeJsonResponse("ok","DEKs",{ {"deks",oss.str()} });
            SSL_write(ssl, resp.c_str(), resp.size());
        } else {
            resp = makeJsonResponse("error","unknown action");
            SSL_write(ssl, resp.c_str(), resp.size());
        }
    } catch (const std::exception &ex) {
        resp = makeJsonResponse("error", std::string("exception: ") + ex.what());
        SSL_write(ssl, resp.c_str(), resp.size());
    }
    std::cout << "Response : " << resp << std::endl;
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

// -------------------- Main Server --------------------
int main() {
    int port = 8443;

    KeyVault vault("./KeyLocker");
    AzureHSM hsm(vault,"user_DEK_permissions.txt");
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

    std::cout << "AzureHSM server listening on port " << port << "\n";

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
