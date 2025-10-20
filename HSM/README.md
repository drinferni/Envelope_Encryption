# Software HSM Implementation

This project is a C++ implementation of a software Hardware Security Module (HSM) based on a provided design blueprint. It uses the OpenSSL library for all cryptographic operations and demonstrates key management principles like secure storage, access control, and envelope encryption.

## Features

-   **Key Storage Vault**: Securely stores keys encrypted at rest using a master key derived from a password.
-   **Cryptographic Engine**: Performs AES-256-GCM encryption/decryption.
-   **Access Control**: Role-based access control managed via a `policies.json` file.
-   **Key Lifecycle Management**: Supports key creation and rotation.
-   **Envelope Encryption**: Implements the envelope encryption pattern for securing data.
-   **Command-Line Interface**: All operations are exposed through a simple CLI.

## Prerequisites

1.  **C++ Compiler**: A modern C++ compiler (supporting C++17).
2.  **CMake**: Version 3.10 or higher.
3.  **OpenSSL**: The development libraries for OpenSSL (e.g., `libssl-dev` on Debian/Ubuntu).
4.  **nlohmann/json**: A header-only JSON library for C++.

## 🛠️ Setup and Build Instructions

### 1. Initial Setup

Clone or download the project and navigate into the directory.

Create the required directories and files:

```bash
# Create the directory to store encrypted keys
mkdir vault

# Create the directory for third-party includes
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
        "CREATE_KEY",
        "ROTATE_KEY"
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
# Create a build directory
mkdir build && cd build

# Configure the project
cmake ..

# Build the executable
make
```

The compiled `hsm` executable will be in the `build/` directory. For ease of use, you can copy it to the project root.

```bash
cp hsm ..
cd ..
```

## 🚀 How to Communicate with the HSM

The HSM is operated via the command line. Before running, you **must** set the master password as an environment variable. This password is used to derive the key that encrypts all other keys in the vault.

```bash
export HSM_MASTER_PASSWORD="my-super-secret-password-123"
```

### Available Commands

#### 1. Create a Key

Create a new AES-256 key. This action requires a principal with `CREATE_KEY` permission.

```bash
./hsm create_key --key_id my-data-key --user admin
# Output: Key 'my-data-key' created successfully.
```

#### 2. Encrypt Data

Encrypt a piece of data using a key. This uses the envelope encryption pattern. The output is a JSON bundle containing the ciphertext and the wrapped data key.

```bash
./hsm encrypt --key_id my-data-key --user app_user --data "this is a secret message"
# Output:
# Encryption successful. Bundle:
# {"ciphertext":"...","data_iv":"...","data_tag":"...","dek_iv":"...","dek_tag":"...","key_id":"my-data-key","wrapped_dek":"..."}
```

#### 3. Decrypt Data

Decrypt a JSON bundle to retrieve the original plaintext.

```bash
# Note: The JSON bundle must be passed as a single string.
./hsm decrypt --user app_user --bundle '{"ciphertext":"...","data_iv":"...","data_tag":"...","dek_iv":"...","dek_tag":"...","key_id":"my-data-key","wrapped_dek":"..."}'
# Output:
# Decryption successful. Plaintext:
# this is a secret message
```

#### 4. Rotate a Key

Generate a new version of an existing key. This is critical for security compliance.

```bash
./hsm rotate_key --key_id my-data-key --user admin
# Output: Key 'my-data-key' rotated successfully.
```