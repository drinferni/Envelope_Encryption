
# Software HSM Implementation

This project is a C++ implementation of a software Hardware Security Module (HSM). It runs as a **secure SSL/TLS server** that accepts JSON-based requests to perform cryptographic operations. It uses the OpenSSL library and demonstrates key management principles like secure storage, access control, and envelope encryption.

## Features

-   **Auto-Generated Certificates**: Automatically creates a self-signed SSL certificate and private key on first launch.
-   **Secure API Server**: Runs as a daemon, communicating over a TLS-encrypted socket.
-   **JSON-RPC Style**: Accepts and returns easy-to-parse JSON messages.
-   **Key Storage Vault**: Securely stores keys encrypted at rest using a master key derived from a password.
-   **Cryptographic Engine**: Performs AES-256-GCM encryption/decryption.
-   **Access Control**: Role-based access control managed via a `policies.json` file.
-   **Key Lifecycle Management**: Supports key creation and rotation.
-   **Envelope Encryption**: Implements the envelope encryption pattern for securing data.

## Prerequisites

1.  **C++ Compiler**: A modern C++ compiler (supporting C++17).
2.  **CMake**: Version 3.10 or higher.
3.  **OpenSSL**: The development libraries (e.g., `libssl-dev` on Debian/Ubuntu).
4.  **nlohmann/json**: A header-only JSON library for C++.

## 🛠️ Setup and Build Instructions

### 1. Initial Setup

Clone or download the project and navigate into the directory. Create the required directories and files:

```bash
mkdir vault
mkdir include
```

### 2. Get nlohmann/json

Download the single header file `json.hpp` from the [nlohmann/json repository](https://github.com/nlohmann/json/releases) and place it inside the `include/` directory.

```bash
wget [https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp](https://github.com/nlohmann/json/releases/download/v3.11.2/json.hpp) -O include/json.hpp
```

### 3. Create Policy File

Create a file named `policies.json` in the project root. This file defines which "principals" (users/roles) can perform which actions.

**`policies.json` example:**
```json
{
    "admin": [
        "CREATE_KEY"
    ],
    "app_user": [
        "ENCRYPT",
        "DECRYPT"
    ]
}
```

### 4. Build the Project

Use CMake to configure and build the executable.

```bash
mkdir build && cd build
cmake ..
make
# Copy the executable to the root directory for convenience
cp hsm ..
cd ..
```

## 🚀 How to Communicate with the HSM

### 1. Start the Server

First, set the master password as an environment variable and run the server. It will listen on port **8443**.

**On the very first run**, the server will automatically generate `server.key` and `server.crt` for SSL/TLS communication.

```bash
# Set the password that protects all keys at rest
export HSM_MASTER_PASSWORD="my-super-secret-password-123"

# Run the server
./hsm
# First run output:
# Generating new self-signed certificate and private key...
# Successfully created server.key and server.crt.
# HSM Server listening on port 8443
```

The server will now be running. You can connect to it from another terminal.

### 2. Connect with a Client

Use the `openssl s_client` tool to establish a secure connection. The `-quiet` flag is recommended to hide verbose connection info.

```bash
openssl s_client -connect localhost:8443 -quiet
```

Once connected, you can type or paste your JSON request and press Enter.

### API Commands (JSON Format)

#### A. Create a Key

* **Request**:
    ```json
    {
      "command": "create_key",
      "user": "admin",
      "params": {
        "key_id": "my-api-key"
      }
    }
    ```

* **Response**:
    ```json
    {"status":"success","message":"Key 'my-api-key' created."}
    ```

#### B. Encrypt Data

* **Request**:
    ```json
    {
      "command": "encrypt",
      "user": "app_user",
      "params": {
        "key_id": "my-api-key",
        "data": "sensitive information"
      }
    }
    ```

* **Response** (contains the encrypted bundle):
    ```json
    {"status":"success","data":{"bundle":"{\"ciphertext\":\"...\",\"data_iv\":\"...\"}"}}
    ```