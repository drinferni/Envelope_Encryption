# ☁️ AWS KMS - Envelope Encryption Protocol (HSM-Based)

This module implements the **Envelope Encryption protocol** used by **AWS Key Management Service (KMS)** to manage, protect, and securely distribute cryptographic keys.  
It builds upon the foundational components provided in the `HSM/` folder, namely:
- `AccessController`
- `KeyVault`
- `BaseCryptoProcessor`

Together, these components emulate how AWS KMS interacts with a Hardware Security Module (HSM) for key lifecycle management.

---

## 🧠 Overview

Envelope encryption is a layered encryption strategy used to protect data keys (DEKs) with higher-level customer master keys (CMKs).  
In this implementation, the **AWSHSM** class handles this process using the simulated HSM backend, maintaining both key hierarchy and access control.

---

## 🧩 Components

### 1. AWSHSM
The **AWSHSM** class implements the **AWS envelope encryption workflow** using the internal KeyVault and AccessController from the HSM module.

#### 🔐 Core Responsibilities

- **Wrap / Unwrap Operations:**  
  Provides `wrapKey()` and `unwrapKey()` functions to encrypt or decrypt a child key using a parent key.  
  Before performing the operation, the system verifies:
  1. The user’s permissions via the AccessController.  
  2. The existence of both parent and child keys in the KeyVault.

- **Customer Master Key (CMK) Management:**  
  Implements `generateCMK()` to create and store CMKs.  
  - Only **AES keys** are generated, as AWS KMS supports AES-based CMKs.
  - Each CMK is encrypted by the **HSM Master Key** before being stored securely in the vault.
  - Since AWS only supports AES-KW and AES-KWP key wrapping CMK can only be a AES key.

- **Key Ownership and Access Control:**  
  Maintains a persistent **mapping between users and their CMKs**, ensuring that only authorized users can use their keys for wrapping and unwrapping operations.

- **Data Key Generation:**  
  Supports both AWS-style Data Encryption Key (DEK) generation APIs:
  - `generateDataKey()` – returns both plaintext and encrypted DEK.
  - `generateDataKeyWithoutPlaintext()` – returns only the encrypted DEK.
  
  The DEK is created inside the KeyVault, wrapped with the user’s CMK, and then the CMK itself is re-wrapped with the Master Key.

- **Persistence:**  
  All metadata (user–key mappings, CMK–DEK relationships) are **persisted to files** to maintain state across program executions.

#### 🧮 Internal Key Hierarchy

```

Master Key (HSM internal, AES)
│
└── Customer Master Keys (CMKs)
│
└── Data Encryption Keys (DEKs)

```

Each layer encrypts the one below it, forming a trust chain rooted in the Master Key that never leaves the HSM.

---

### 2. AWS Server

The **AWS_server** acts as the **backend service** that exposes the AWS KMS-like API over secure SSL connections.

#### ⚙️ Features
- Establishes an **SSL/TLS socket connection** with clients for encrypted communication.  
- Accepts JSON-formatted requests to perform operations:
  - `generateCMK`
  - `generateDataKey`
  - `generateDataKeyWithoutPlaintext`
  - `grantCmkAccess` (share CMK ownership)
- Returns JSON-formatted responses for consistency and easier validation.  
- Ensures message integrity by parsing complete JSON payloads (no partial request handling). 

#### 🔒 Security
- All payloads are encrypted using **SSL sockets**, providing transport-layer confidentiality in addition to key-level encryption within the HSM.

---

### 3. AWS Client

The **AWS_client** is a **test client utility** designed to interact with the AWS_server and verify the system’s functionality.

#### 🧪 Capabilities
- Connects securely to the `AWS_server` using SSL.
- Sends requests for:
  - Generating CMKs
  - Generating DEKs
  - Retrieving encrypted keys
- Validates responses and demonstrates how AWS envelope encryption operates in practice.

This serves as a **demonstration and testing interface**.

## 📘 Summary

This implementation of **AWS Envelope Encryption** simulates a complete KMS-HSM integration pipeline:

* Keys are **securely generated, wrapped, and managed** within a software-based HSM.
* Data keys and master keys follow AWS-style cryptographic protocols.
* Communication between client and server is **SSL-encrypted**, ensuring authenticity and confidentiality.

Together, these components form a functional educational model of how **AWS KMS** operates internally using **hardware-backed encryption** for key protection.

---

**Author:** Ansh Meshram
**Language:** C++17
**Dependencies:** OpenSSL, Standard C++ STL
