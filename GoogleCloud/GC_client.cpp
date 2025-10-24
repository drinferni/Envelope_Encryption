#include <iostream>
#include <string>
#include <map>
#include <sstream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

// -------------------- Helpers --------------------
std::string makeJsonRequest(const std::map<std::string, std::string> &kv)
{
    std::ostringstream oss;
    oss << "{";
    bool first = true;
    for (auto &p : kv)
    {
        if (!first)
            oss << ",";
        oss << "\"" << p.first << "\":\"" << p.second << "\"";
        first = false;
    }
    oss << "}";
    return oss.str();
}

SSL *ssl_connect(const std::string &host, int port)
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
        return nullptr;

    SSL *ssl = SSL_new(ctx);
    BIO *bio = BIO_new_ssl_connect(ctx);
    if (!bio)
        return nullptr;

    std::string target = host + ":" + std::to_string(port);
    BIO_set_conn_hostname(bio, target.c_str());

    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    if (BIO_do_connect(bio) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    if (SSL_connect(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    return ssl;
}

std::string sendRequest(const std::string &host, int port, const std::map<std::string, std::string> &req)
{
    SSL *ssl = ssl_connect(host, port);
    if (!ssl)
        return "SSL connection failed";

    std::string reqStr = makeJsonRequest(req) + "\n";
    SSL_write(ssl, reqStr.c_str(), reqStr.size());

    char buf[4096];
    int n = SSL_read(ssl, buf, sizeof(buf) - 1);
    std::string resp;
    if (n > 0)
    {
        buf[n] = '\0';
        resp = std::string(buf);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    return resp;
}

// -------------------- Random Key Generator --------------------
std::string generateRandomHexKey(size_t bytes = 16)
{
    unsigned char buffer[bytes];
    if (RAND_bytes(buffer, bytes) != 1)
    {
        throw std::runtime_error("Failed to generate random key");
    }
    std::ostringstream oss;
    for (size_t i = 0; i < bytes; i++)
    {
        oss << std::hex << (buffer[i] >> 4);
        oss << std::hex << (buffer[i] & 0xF);
    }
    return oss.str();
}

// Simple key-value JSON parser
std::map<std::string, std::string> parseSimpleJson(const std::string &s)
{
    std::map<std::string, std::string> out;
    bool inKey = true;
    std::string key, val;
    bool inStr = false;
    char delim = '"';
    for (size_t i = 0; i < s.size(); ++i)
    {
        char c = s[i];
        if (c == '{' || c == '}' || c == ',')
            continue;
        if (c == '"' && !inStr)
        {
            inStr = true;
            continue;
        }
        if (c == '"' && inStr)
        {
            inStr = false;
            if (inKey)
            {
                inKey = false;
            }
            else
            {
                out[key] = val;
                key.clear();
                val.clear();
                inKey = true;
            }
            continue;
        }
        if (inStr)
        {
            if (inKey)
                key.push_back(c);
            else
                val.push_back(c);
        }
        else if (c == ':')
            continue;
        else if (!inKey)
            val.push_back(c);
    }
    return out;
}
// -------------------- Main --------------------
int main()
{
    std::string host = "127.0.0.1";
    int port = 8443;

    std::string alice = "alice";
    std::string alicePass = "alice123";
    // -------------------- AES-KWP Flow --------------------
    std::string cmk = "GCK1";

    // 1. Generate CryptoKey AES-KWP
    auto resp1 = sendRequest(host, port, {{"username", alice}, {"password", alicePass}, {"action", "generateCryptoKey"}, {"keyname", cmk}, {"algo", "AES-KWP"}});
    std::cout << "generateCryptoKey AES-KWP: " << resp1 << "\n";

    // 2. Encrypt first random DEK
    std::string dek1 = generateRandomHexKey();
    auto resp2 = sendRequest(host, port, {{"username", alice}, {"password", alicePass}, {"action", "encrypt"}, {"keyname", cmk}, {"childKey", dek1}});
    std::cout << "encrypt DEK1 AES-KWP: " << resp2 << "\n";
    std::string cipher1 = parseSimpleJson(resp2)["ciphertext"];

    // 3. Encrypt second random DEK
    std::string dek2 = generateRandomHexKey();
    auto resp3 = sendRequest(host, port, {{"username", alice}, {"password", alicePass}, {"action", "encrypt"}, {"keyname", cmk}, {"childKey", dek2}});
    std::cout << "encrypt DEK2 AES-KWP: " << resp3 << "\n";

    // 4. Decrypt first DEK using its ciphertext
    auto resp4 = sendRequest(host, port, {{"username", alice}, {"password", alicePass}, {"action", "decrypt"}, {"keyname", cmk}, {"childKey", cipher1}});
    std::cout << "decrypt DEK1 AES-KWP from ciphertext: " << resp4 << "\n";
    std::string decrypted1 = parseSimpleJson(resp4)["plaintext"];

    // 5. Verify AES-KWP
    std::cout << "\nVerification AES-KWP:\n";
    std::cout << "Original DEK1: " << dek1 << "\n";
    std::cout << "Decrypted DEK1: " << decrypted1 << "\n";
    if (dek1 == decrypted1)
        std::cout << "✅ DEK1 AES-KWP matches!\n";
    else
        std::cout << "❌ DEK1 AES-KWP mismatch!\n";

    // -------------------- RSA-OAEP Flow --------------------
    std::string cmk2 = "GCK2";

    // 1. Generate CryptoKey RSA-OAEP
    auto resp1b = sendRequest(host, port, {{"username", alice}, {"password", alicePass}, {"action", "generateCryptoKey"}, {"keyname", cmk2}, {"algo", "AES-KW"}});
    std::cout << "generateCryptoKey RSA-OAEP: " << resp1b << "\n";

    // 2. Encrypt first random DEK for RSA-OAEP
    std::string dek3 = generateRandomHexKey();
    auto resp2b = sendRequest(host, port, {{"username", alice}, {"password", alicePass}, {"action", "encrypt"}, {"keyname", cmk2}, {"childKey", dek3}});
    std::cout << "encrypt DEK1 RSA-OAEP: " << resp2b << "\n";
    std::string cipher3 = parseSimpleJson(resp2b)["ciphertext"];

    // 3. Encrypt second random DEK for RSA-OAEP
    std::string dek4 = generateRandomHexKey();
    auto resp3b = sendRequest(host, port, {{"username", alice}, {"password", alicePass}, {"action", "encrypt"}, {"keyname", cmk2}, {"childKey", dek4}});
    std::cout << "encrypt DEK2 RSA-OAEP: " << resp3b << "\n";

    // 4. Decrypt first DEK using its ciphertext
    auto resp4b = sendRequest(host, port, {{"username", alice}, {"password", alicePass}, {"action", "decrypt"}, {"keyname", cmk2}, {"childKey", cipher3}});
    std::cout << "decrypt DEK1 RSA-OAEP from ciphertext: " << resp4b << "\n";
    std::string decrypted3 = parseSimpleJson(resp4b)["plaintext"];

    // 5. Verify RSA-OAEP
    std::cout << "\nVerification RSA-OAEP:\n";
    std::cout << "Original DEK1: " << dek3 << "\n";
    std::cout << "Decrypted DEK1: " << decrypted3 << "\n";
    if (dek3 == decrypted3)
        std::cout << "✅ DEK1 RSA-OAEP matches!\n";
    else
        std::cout << "❌ DEK1 RSA-OAEP mismatch!\n";

    return 0;
}
