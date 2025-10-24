#include <iostream>
#include <string>
#include <sstream>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <unistd.h>

// -------------------- Helpers --------------------
std::string makeJsonRequest(const std::string& username, const std::string& password,
                            const std::string& action,
                            const std::string& keyname = "",
                            const std::string& device = "",
                            const std::string& mapping = "") {
    std::ostringstream oss;
    oss << "{";
    oss << "\"username\":\"" << username << "\",";
    oss << "\"password\":\"" << password << "\",";
    oss << "\"action\":\"" << action << "\"";
    if (!keyname.empty()) oss << ",\"keyname\":\"" << keyname << "\"";
    if (!device.empty())  oss << ",\"device\":\"" << device << "\"";
    if (!mapping.empty()) oss << ",\"mapping\":\"" << mapping << "\"";
    oss << "}";
    return oss.str();
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

// -------------------- Main --------------------
int main() {
    std::string server_ip = "127.0.0.1";
    int port = 8443;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        std::cerr << "Failed to create SSL_CTX\n";
        return 1;
    }

    SSL* ssl;
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, server_ip.c_str(), &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        return 1;
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    std::string username = "alice";
    std::string password = "alice123";

    // -------------------- Demo: Generate DEK --------------------
    std::string generateDEKReq = makeJsonRequest(username, password, "generateDEK", "myDEK");
    SSL_write(ssl, generateDEKReq.c_str(), generateDEKReq.size());
    SSL_write(ssl, "\n", 1);

    std::string response = ssl_read_line(ssl);
    std::cout << "Response (generateDEK): " << response << "\n";

    // -------------------- Demo: Encrypt volume --------------------
    std::string device = "/dev/loop0";
    std::string encryptReq = makeJsonRequest(username, password, "encryptVolume", "myDEK", device);
    SSL_write(ssl, encryptReq.c_str(), encryptReq.size());
    SSL_write(ssl, "\n", 1);

    response = ssl_read_line(ssl);
    std::cout << "Response (encryptVolume): " << response << "\n";

    // -------------------- Demo: Open volume --------------------
    std::string mapping = "secure-disk";
    std::string openReq = makeJsonRequest(username, password, "openVolume", "myDEK", device, mapping);
    SSL_write(ssl, openReq.c_str(), openReq.size());
    SSL_write(ssl, "\n", 1);

    response = ssl_read_line(ssl);
    std::cout << "Response (openVolume): " << response << "\n";

    // -------------------- Demo: Close volume --------------------
    std::string closeReq = makeJsonRequest(username, password, "closeVolume", "", "", mapping);
    SSL_write(ssl, closeReq.c_str(), closeReq.size());
    SSL_write(ssl, "\n", 1);

    response = ssl_read_line(ssl);
    std::cout << "Response (closeVolume): " << response << "\n";

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);

    return 0;
}
