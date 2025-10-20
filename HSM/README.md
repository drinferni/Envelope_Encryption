Software HSM Implementation in C++ with OpenSSL

This project is a software simulation of a Hardware Security Module (HSM) that runs as a secure TLS server. It provides cryptographic functionalities like key generation, encryption, decryption, and signing over a network via a JSON-based API, while enforcing access control and managing the key lifecycle.

Project Structure

The project is organized into several components, each represented by a C++ class:

AccessController: Manages user authentication and authorization.

KeyVault: Handles the secure storage and management of cryptographic keys.

CryptoEngine: Performs all cryptographic operations using OpenSSL.

HSM: The main class that orchestrates the different components and exposes the HSM's functionality.

main.cpp: The entry point of the application, which runs the TLS server.

The project directory is structured as follows:

/HSM
|-- AccessController.h
|-- AccessController.cpp
|-- KeyVault.h
|-- KeyVault.cpp
|-- CryptoEngine.h
|-- CryptoEngine.cpp
|-- HSM.h
|-- HSM.cpp
|-- main.cpp
|-- users.tsv
|-- passwords.tsv
|-- cert.pem       <-- You will generate this
|-- key.pem        <-- You will generate this
|-- KeyFolder/


Configuration Files

The HSM uses two TSV (Tab-Separated Values) files for configuration:

passwords.tsv

This file stores user credentials. Each line represents a user with their username and the SHA-256 hash of their password, separated by a tab.
Format: <username>\t<password_hash>

users.tsv

This file defines the access control list, specifying which operations each user is permitted to perform.
Format: <username>\t<permission1> <permission2> ...

How to Compile and Run

Prerequisites

A C++ compiler (g++)

OpenSSL library and headers installed (libssl-dev on Debian/Ubuntu)

1. Generate TLS Certificate

First, you need to generate a self-signed certificate and a private key for the server to use for TLS. Run the following command:

openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes -subj "/CN=localhost"


This will create cert.pem and key.pem in your project directory.

2. Compilation

Compile the project using the following g++ command:

g++ main.cpp HSM.cpp AccessController.cpp KeyVault.cpp CryptoEngine.cpp -o hsm_server -lssl -lcrypto


3. Running the HSM Server

To run the HSM, execute the compiled binary:

./hsm_server


The server will start and listen for secure connections on port 8443.

JSON API

The server accepts requests in JSON format. All data for encryption, decryption, or signing must be Base64 encoded.

API Commands

Create Key

Request:

{
  "command": "create-key",
  "username": "admin",
  "password": "your_password",
  "key_name": "new-aes-key"
}


Response:

{"status":"success","message":"Key created successfully.","data":""}


Encrypt Data

Request:

{
  "command": "encrypt",
  "username": "user1",
  "password": "user_password",
  "key_name": "my-aes-key",
  "data": "BASE64_ENCODED_PLAINTEXT"
}


Response:

{"status":"success","message":"Data encrypted.","data":"BASE64_ENCODED_CIPHERTEXT"}


Decrypt Data

Request:

{
  "command": "decrypt",
  "username": "user1",
  "password": "user_password",
  "key_name": "my-aes-key",
  "data": "BASE64_ENCODED_CIPHERTEXT"
}


Response:

{"status":"success","message":"Data decrypted.","data":"BASE64_ENCODED_PLAINTEXT"}


Sign Data

Request:

{
  "command": "sign",
  "username": "admin",
  "password": "your_password",
  "key_name": "my-signing-key",
  "data": "BASE64_ENCODED_DATA_TO_SIGN"
}


Response:

{"status":"success","message":"Data signed.","data":"BASE64_ENCODED_SIGNATURE"}


How to Connect (Example using OpenSSL)

You can use the openssl s_client tool to connect to the server and send JSON requests.

Start the server: ./hsm_server

In another terminal, connect with s_client:

openssl s_client -connect localhost:8443


Once connected, paste your JSON request and press Enter twice. The server will process the request and send back a JSON response.