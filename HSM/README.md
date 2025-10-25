# 🔐 Hardware Security Module (HSM) - Cloud KMS Emulator

This project implements a **software-based Hardware Security Module (HSM)** that emulates the core functionalities of HSMs used in major cloud Key Management Services (KMS) such as **AWS**, **Google Cloud**, and **Microsoft Azure**.

The system is modular and contains **three primary shared components** — `AccessController`, `KeyVault`, and `BaseCryptoProcessor` — which serve as the backbone for the three cloud integrations.

---

## 🧩 Components Overview

### 1. AccessController
The **AccessController** class emulates the **IAM (Identity and Access Management)** policies used by cloud platforms to authenticate users and manage access control.

- **Authentication:**  
  User authentication is performed using passwords. Each password is **hashed using SHA-256** to ensure confidentiality even if the stored data is compromised.

- **Access List Management:**  
  Access permissions for each user are loaded from a **TSV (Tab-Separated Values)** file, which maps users to their allowed actions and resources.

---

### 2. KeyVault
The **KeyVault** is the central component of the HSM and is responsible for securely managing cryptographic keys and their metadata.

- **Data Structure:**  
  The vault defines a structure `KeyData`, which contains:
  - `keyName` – the unique identifier for the key  
  - `parentKey` – the key used to wrap this key  
  - `publicKey` and `privateKey` – depending on the key type; for symmetric keys, `publicKey` stores the actual key material  

- **Storage:**  
  All keys and metadata are securely stored in a dedicated `storage/` directory managed by the `KeyVault` class.

- **Key Management Capabilities:**  
  - Generate and store **AES**, **RSA**, and **EC** keys.  
  - Retrieve keys securely from the vault.  
  - Delete all keys in case of a **physical breach** (emulating a real HSM’s zeroization behavior).  

- **Master Key:**  
  The `KeyVault` maintains a **Master AES Key** which **never leaves the HSM**.  
  This master key encrypts top-level keys (CMKs / KEKs / CryptoKeys):
  - **AWS:** Customer Master Key (CMK)
  - **Google Cloud:** CryptoKey
  - **Azure:** Key Encrypting Key (KEK)

  This ensures all root cryptographic material is securely wrapped and never exposed in plaintext.

---

### 3. BaseCryptoProcessor
The **BaseCryptoProcessor** simulates the **dedicated cryptographic processor** within an HSM responsible for performing all cryptographic operations in isolation.

- **Integration with KeyVault:**  
  Each processor instance holds a dedicated `KeyVault` object to access and manage cryptographic materials.

- **Core Functionalities:**  
  - **Wrap / Unwrap (AWS):**  
    Wraps and unwraps keys using a parent key.  
    Example: wrapping a child key under a parent CMK using AES-KW, AES-KWP, or RSA-OAEP.

  - **Encrypt / Decrypt (Google Cloud):**  
    Performs symmetric encryption/decryption operations on Key data directly using provided key material returning the result.

- **Supported Algorithms:**  
  - **AES-KW (AES Key Wrap):**  
    Wraps keys using AES in ECB mode with a fixed IV of `A6A6A6A6A6A6A6A6`.  
    Provides integrity checking via a final authentication step.  
  - **AES-KWP (AES Key Wrap with Padding):**  
    Extension of AES-KW allowing keys of arbitrary length with padding.  
  - **RSA-OAEP (Optimal Asymmetric Encryption Padding):**  
    Uses RSA public/private key pairs with OAEP padding and typically SHA-1 or SHA-256 hash during encryption.

- **Wrap Log:**  
  The processor maintains a **wrap log** recording which key wrapped which other key, enabling auditable traceability within the HSM.

## 🧪 Testing

Unit tests and demonstration files are provided to validate:

* User authentication and access control
* Key creation, wrapping, and retrieval
* Encryption and decryption functionality
* Proper handling of zeroization events

---

## ☁️ Cloud Integration

Each cloud KMS (AWS, Google Cloud, and Azure) component interacts with the shared HSM classes to emulate their respective key lifecycle management processes:

* **AWS:** Key wrapping/unwrapping via CMKs using AES-KWP.
* **Google Cloud:** Direct data encryption/decryption using CryptoKeys.
* **Azure:** Key wrapping and key encryption hierarchy using KEKs.

---

## 📘 Summary

This HSM emulator acts as a **trust anchor** for all cryptographic operations and key lifecycle management within the emulated cloud KMS environments. It demonstrates how hardware-backed security principles can be simulated in software for educational and experimental purposes.

---

**Author:** Ansh Meshram
**Language:** C++17
**Dependencies:** OpenSSL, Standard C++ STL
