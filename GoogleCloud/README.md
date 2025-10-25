<!-- The fucntin implements the encrlope encrytion protocol used in GC KEM to manage and safegaurd keys. It uses the components of the HSM folder.

Google Cloud HSM 
    -> This fucntion implments the protocol.
    -> It has the funciton to genreate CryptoKey keys. This gerneated can be AES or RSA key  These keys are then encrypted by the Master key of the vault and then stored.
    -> It also maintains a map denoting which keys belong to with users hence resticting the who all can get the key and use it to wrapo and unwrap keys.
    -> The DEK is provied by the user which is then encrypted or decrypted by the required CryptoKey. The reuslt are then resturned to the user
    -> These function take the DEK , decrypt the required CryptoKey and then wrap it with the CryptoKey and store it. The CryptoKey is then also wraped with the master key and stored.
    -> The class also contains a map which corresponds to the DEK and the CryptoKey stored
    -> all the data in the maps are persistent as they are loaded and saved from files.

GC_server
    -> this acts as the backend of the KMS. It uses ssl socket to connect to the client exposing them function to generateCryptoKey, encypt and decypt as well as transfer to share ownership of the CryptoKey keys. 
    -> the request are in Json format which are the common format used. This make is easy to know if we have resieved all the data making sure that we don't work with half informations
    -> SSL socket encrypted their payload hance adding a layer of security

GC_client 
    -> it is a test client that connect to the server to test its capabilities

Makfile and envgen.cpp are provided  -->

# 🔐 Google Cloud KMS - Envelope Encryption Protocol (HSM-Backed Implementation)

This module implements the **Envelope Encryption protocol** used by **Google Cloud Key Management Service (KMS)** for secure key lifecycle management and protection.  
It leverages the foundational components defined in the `HSM/` directory:
- `AccessController`  
- `KeyVault`  
- `BaseCryptoProcessor`  

The system emulates how Google Cloud’s KMS interacts with an underlying **Hardware Security Module (HSM)** to generate, store, wrap, and unwrap keys using secure cryptographic algorithms.

---

## 🧠 Overview

In Google Cloud KMS, cryptographic operations are performed using **CryptoKeys** managed under a master key hierarchy.  
This implementation mirrors that design — the **GoogleCloudHSM** class orchestrates CryptoKey management, DEK encryption/decryption, and ownership control while ensuring secure key wrapping through **standardized cryptographic algorithms**.

---

## 🧩 Components

### 1. GoogleCloudHSM

The **GoogleCloudHSM** class implements the core logic of Google Cloud’s **envelope encryption** protocol, integrated tightly with the simulated HSM environment.

#### 🔐 Core Responsibilities

- **CryptoKey Generation:**  
  Implements `generateCryptoKey()` to create new cryptographic keys.  
  - Supported key types: **AES** (symmetric) and **RSA** (asymmetric).  
  - Each CryptoKey is encrypted (wrapped) with the **HSM Master Key** before being persisted in the KeyVault.  
  - AES keys are primarily used for high-performance symmetric encryption, while RSA keys provide asymmetric key wrapping capabilities.

- **User and Ownership Mapping:**  
  Maintains a **persistent user-to-key mapping**, ensuring that each CryptoKey is accessible only to its owner.  
  Unauthorized users cannot perform encryption or decryption using restricted keys.

- **Envelope Encryption of DEKs:**  
  Accepts user-supplied **Data Encryption Keys (DEKs)** that are then:
  1. Wrapped (encrypted) or unwrapped (decrypted) using the corresponding CryptoKey.  
  2. The CryptoKey itself is decrypted from the vault, used for the operation, then securely re-wrapped with the HSM Master Key.  
  3. All mappings between DEKs and CryptoKeys are maintained in persistent files.

- **Persistent State Management:**  
  The module serializes user–key mappings and DEK–CryptoKey relationships to disk, ensuring the HSM’s internal state persists across runs.

---

## ⚙️ Supported Wrapping Algorithms

The **GoogleCloudHSM** supports the three industry-standard key wrapping algorithms used by modern KMS implementations:

### 1. **AES-KW (AES Key Wrap)**
- Standard: [RFC 3394](https://datatracker.ietf.org/doc/html/rfc3394)  
- Mode: AES in ECB mode with a **fixed IV** (`0xA6A6A6A6A6A6A6A6`)  
- Designed specifically for **key wrapping** with integrity verification.  
- Provides deterministic output and protection against key tampering.

### 2. **AES-KWP (AES Key Wrap with Padding)**
- Standard: [RFC 5649](https://datatracker.ietf.org/doc/html/rfc5649)  
- Extension of AES-KW allowing wrapping of keys with **non-multiple-of-64-bit lengths**.  
- Uses a variable IV (`0xA65959A6A65959A6`) and applies **padding** to align data.  
- Preferred for wrapping arbitrary-length key material.

### 3. **RSA-OAEP (Optimal Asymmetric Encryption Padding)**
- Based on the RSA algorithm with **OAEP padding** (RFC 8017).  
- Provides **asymmetric key wrapping**, suitable when distributing wrapped DEKs across trust domains.  
- Uses SHA-256 as the default hash and MGF1 for mask generation.

Each wrapping algorithm is implemented using OpenSSL’s cryptographic primitives through the `BaseCryptoProcessor` class, ensuring compliance with cryptographic best practices.

---

## 🧮 Key Hierarchy

```

Master Key (HSM internal AES key)
│
└── CryptoKeys (AES or RSA)
│
└── Data Encryption Keys (DEKs)

```

This hierarchical encryption model mirrors **Google Cloud KMS’s keyring architecture**, where the master key never leaves the HSM, ensuring top-level trust anchoring.

---

### 2. GC_Server

The **GC_server** acts as the **backend service** of the emulated Google Cloud KMS.

#### ⚙️ Features
- Provides a secure **SSL/TLS socket interface** for client communication.
- Supports JSON-formatted API requests for:
  - `generateCryptoKey`
  - `encrypt`
  - `decrypt`
  - `transfer` (for sharing key ownership)
- Ensures message integrity by validating the completeness of JSON payloads before execution.
- Uses the shared `NIC` class for encrypted transport and message framing.

#### 🔒 Security
- All communications are encrypted using **SSL/TLS**, providing confidentiality and authentication at the transport layer.  
- Combined with key-level encryption from the HSM, this creates **defense-in-depth** across communication and storage layers.

---

### 3. GC_Client

The **GC_client** is a **testing utility** designed to interact with the GC_server and validate all functionalities.

#### 🧪 Capabilities
- Connects securely to the server via SSL.  
- Sends structured JSON requests to:
  - Generate new CryptoKeys (AES or RSA)  
  - Encrypt and decrypt DEKs using selected wrapping algorithms  
  - Test access restrictions and ownership transfer  
- Displays the returned responses for validation and debugging.


## 🧪 Testing and Verification

The provided test scripts and utilities verify:

* CryptoKey generation (AES and RSA)
* DEK encryption/decryption with AES-KW, AES-KWP, and RSA-OAEP
* Proper ownership and permission enforcement
* Secure client-server data exchange over SSL
* Persistence of user–key relationships and wrapped key data

---

## 📘 Summary

This implementation provides a full emulation of **Google Cloud KMS’s envelope encryption** process, supported by an HSM-based trust model.
It demonstrates:

* **Hierarchical key management** (MasterKey → CryptoKey → DEK)
* **Multiple key wrapping algorithms:** AES-KW, AES-KWP, RSA-OAEP
* **Access-controlled key usage** with persistent ownership tracking
* **Encrypted SSL communication** for secure KMS interactions

This software model offers a practical and educational framework to study **cloud-scale cryptographic key management** systems.

---

**Author:** Ansh Meshram
**Language:** C++17
**Dependencies:** OpenSSL, Standard C++ STL
