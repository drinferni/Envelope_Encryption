#include <iostream>
#include <string>
#include <map>
#include <sstream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

// -------------------- Helpers --------------------
std::string makeJsonRequest(const std::map<std::string,std::string>& kv) {
    std::ostringstream oss;
    oss << "{";
    bool first = true;
    for (auto &p : kv) {
        if (!first) oss << ",";
        oss << "\"" << p.first << "\":\"" << p.second << "\"";
        first = false;
    }
    oss << "}";
    return oss.str();
}

SSL* ssl_connect(const std::string& host, int port) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    BIO* bio = BIO_new_ssl_connect(ctx);
    if (!bio) {
        SSL_CTX_free(ctx);
        return nullptr;
    }

    std::string target = host + ":" + std::to_string(port);
    BIO_set_conn_hostname(bio, target.c_str());

    SSL* ssl = nullptr;
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    if (BIO_do_connect(bio) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return nullptr;
    }

    // Store ctx pointer in SSL ex_data for cleanup later
    SSL_set_ex_data(ssl, 0, ctx);
    return ssl;
}

void ssl_disconnect(SSL* ssl) {
    if (!ssl) return;
    SSL_CTX* ctx = (SSL_CTX*)SSL_get_ex_data(ssl, 0);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    if (ctx) SSL_CTX_free(ctx);
}

std::string sendRequest(const std::string& host, int port, const std::map<std::string,std::string>& req) {
    SSL* ssl = ssl_connect(host, port);
    if (!ssl) {
        std::cerr << "SSL connect failed\n";
        return "";
    }

    std::string reqStr = makeJsonRequest(req) + "\n";
    std::cout << "Sending Request: " << reqStr;

    SSL_write(ssl, reqStr.c_str(), reqStr.size());

    char buf[4096];
    int n = SSL_read(ssl, buf, sizeof(buf) - 1);
    if (n <= 0) {
        ssl_disconnect(ssl);
        return "";
    }
    buf[n] = '\0';
    std::string resp(buf);
    ssl_disconnect(ssl);

    std::cout << "Response Got: " << resp << std::endl;
    return resp;
}

// -------------------- Main --------------------
int main() {
    std::string host = "127.0.0.1";
    int port = 8443;

    std::string username = "alice";
    std::string password = "alice123";
    std::string dek = "myDEK";
    std::string device = "/dev/loop0";
    std::string mapping = "secure-disk";

    // 1. Generate DEK
    auto resp1 = sendRequest(host, port, {
        {"username", username},
        {"password", password},
        {"action", "generateDEK"},
        {"keyname", dek}
    });
    std::cout << "generateDEK: " << resp1 << "\n";

    // 2. Encrypt Volume
    auto resp2 = sendRequest(host, port, {
        {"username", username},
        {"password", password},
        {"action", "encryptVolume"},
        {"keyname", dek},
        {"device", device}
    });
    std::cout << "encryptVolume: " << resp2 << "\n";

    // 3. Open Volume
    auto resp3 = sendRequest(host, port, {
        {"username", username},
        {"password", password},
        {"action", "openVolume"},
        {"keyname", dek},
        {"device", device},
        {"mapping", mapping}
    });
    std::cout << "openVolume: " << resp3 << "\n";

    // 4. Close Volume
    auto resp4 = sendRequest(host, port, {
        {"username", username},
        {"password", password},
        {"action", "closeVolume"},
        {"mapping", mapping}
    });
    std::cout << "closeVolume: " << resp4 << "\n";

    return 0;
}
